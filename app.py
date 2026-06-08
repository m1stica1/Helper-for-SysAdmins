from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
NAMES_FILE = ROOT / "device_names.json"
INVENTORY_FILE = ROOT / "inventory.json"
HISTORY_FILE = ROOT / "scan_history.json"
PROFILES_FILE = ROOT / "scan_profiles.json"
MAX_HOSTS = 1024
MAX_HISTORY_ITEMS = 50
DEFAULT_PORTS = [22, 80, 135, 139, 443, 445, 515, 631, 3389, 5000, 5985, 8000, 8080, 9100]
MAX_TOOL_OUTPUT = 12000


@dataclass
class Device:
    ip: str
    device_name: str | None
    name_source: str | None
    hostname: str | None
    mac: str | None
    latency_ms: float | None
    open_ports: list[int]
    last_seen: str


def load_device_names() -> dict:
    if not NAMES_FILE.exists():
        return {"by_ip": {}, "by_mac": {}}
    try:
        with NAMES_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError):
        return {"by_ip": {}, "by_mac": {}}

    return {
        "by_ip": dict(data.get("by_ip", {})),
        "by_mac": dict(data.get("by_mac", {})),
    }


def save_device_names(names: dict) -> None:
    normalized = {
        "by_ip": dict(names.get("by_ip", {})),
        "by_mac": dict(names.get("by_mac", {})),
    }
    with NAMES_FILE.open("w", encoding="utf-8") as file:
        json.dump(normalized, file, ensure_ascii=False, indent=2, sort_keys=True)


def load_inventory() -> dict:
    if not INVENTORY_FILE.exists():
        return {"devices": {}}
    try:
        with INVENTORY_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError):
        return {"devices": {}}
    return {"devices": dict(data.get("devices", {}))}


def save_inventory(inventory: dict) -> None:
    normalized = {"devices": dict(inventory.get("devices", {}))}
    with INVENTORY_FILE.open("w", encoding="utf-8") as file:
        json.dump(normalized, file, ensure_ascii=False, indent=2, sort_keys=True)


def load_history() -> dict:
    if not HISTORY_FILE.exists():
        return {"scans": []}
    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError):
        return {"scans": []}
    return {"scans": list(data.get("scans", []))}


def save_history(history: dict) -> None:
    scans = list(history.get("scans", []))[:MAX_HISTORY_ITEMS]
    with HISTORY_FILE.open("w", encoding="utf-8") as file:
        json.dump({"scans": scans}, file, ensure_ascii=False, indent=2)


def append_scan_history(result: dict) -> None:
    devices = result.get("devices", [])
    open_port_total = sum(len(device.get("open_ports", [])) for device in devices)
    entry = {
        "id": result.get("scannedAt", datetime.now().isoformat(timespec="seconds")),
        "cidr": result.get("cidr"),
        "hostCount": result.get("hostCount", 0),
        "activeCount": result.get("activeCount", 0),
        "openPortTotal": open_port_total,
        "durationSeconds": result.get("durationSeconds", 0),
        "scannedAt": result.get("scannedAt"),
        "ports": result.get("ports", []),
        "devices": devices,
    }
    history = load_history()
    scans = [entry, *history.get("scans", [])]
    history["scans"] = scans[:MAX_HISTORY_ITEMS]
    save_history(history)


def clear_history() -> None:
    save_history({"scans": []})


def default_profiles() -> list[dict]:
    return [
        {
            "id": "office-default",
            "name": "Офисная сеть",
            "cidr": guess_local_cidr(),
            "ports": DEFAULT_PORTS,
            "timeoutMs": 700,
            "concurrency": 96,
            "updatedAt": datetime.now().isoformat(timespec="seconds"),
        },
        {
            "id": "printers",
            "name": "Принтеры",
            "cidr": guess_local_cidr(),
            "ports": [80, 443, 515, 631, 9100],
            "timeoutMs": 900,
            "concurrency": 64,
            "updatedAt": datetime.now().isoformat(timespec="seconds"),
        },
        {
            "id": "windows-admin",
            "name": "Windows/RDP/SMB",
            "cidr": guess_local_cidr(),
            "ports": [135, 139, 445, 3389, 5985],
            "timeoutMs": 900,
            "concurrency": 96,
            "updatedAt": datetime.now().isoformat(timespec="seconds"),
        },
    ]


def load_profiles() -> dict:
    if not PROFILES_FILE.exists():
        profiles = default_profiles()
        save_profiles({"profiles": profiles})
        return {"profiles": profiles}
    try:
        with PROFILES_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError):
        return {"profiles": default_profiles()}
    return {"profiles": list(data.get("profiles", []))}


def save_profiles(data: dict) -> None:
    profiles = list(data.get("profiles", []))
    with PROFILES_FILE.open("w", encoding="utf-8") as file:
        json.dump({"profiles": profiles}, file, ensure_ascii=False, indent=2)


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9А-Яа-яёЁ_-]+", "-", value.strip()).strip("-").lower()
    return slug or f"profile-{int(time.time())}"


def upsert_profile(payload: dict) -> dict:
    name = str(payload.get("name", "")).strip()
    cidr = str(payload.get("cidr", "")).strip()
    ports = parse_ports(payload.get("ports"))
    timeout_ms = int(payload.get("timeoutMs", 700))
    concurrency = int(payload.get("concurrency", 96))

    if not name:
        raise ValueError("Название профиля обязательно.")
    validate_network(cidr, allow_public=False)
    if not 100 <= timeout_ms <= 5000:
        raise ValueError("Таймаут должен быть от 100 до 5000 мс.")

    profile_id = str(payload.get("id", "")).strip() or slugify(name)
    profile = {
        "id": profile_id,
        "name": name,
        "cidr": cidr,
        "ports": ports,
        "timeoutMs": timeout_ms,
        "concurrency": max(1, min(concurrency, 256)),
        "updatedAt": datetime.now().isoformat(timespec="seconds"),
    }

    data = load_profiles()
    profiles = [item for item in data.get("profiles", []) if item.get("id") != profile_id]
    profiles.append(profile)
    data["profiles"] = sorted(profiles, key=lambda item: item.get("name", ""))
    save_profiles(data)
    return profile


def delete_profile(profile_id: str) -> dict:
    data = load_profiles()
    profiles = [item for item in data.get("profiles", []) if item.get("id") != profile_id]
    data["profiles"] = profiles
    save_profiles(data)
    return data


def inventory_key(ip: str, mac: str | None = None) -> str:
    return f"mac:{mac}" if mac else f"ip:{ip}"


def merge_scan_into_inventory(devices: list[Device]) -> None:
    if not devices:
        return

    inventory = load_inventory()
    records = inventory.setdefault("devices", {})
    now = datetime.now().isoformat(timespec="seconds")

    for device in devices:
        key = inventory_key(device.ip, device.mac)
        fallback_key = inventory_key(device.ip)
        record = records.get(key) or records.get(fallback_key) or {}
        if fallback_key in records and key != fallback_key:
            records.pop(fallback_key, None)

        record.update({
            "key": key,
            "ip": device.ip,
            "mac": device.mac,
            "device_name": device.device_name,
            "name_source": device.name_source,
            "hostname": device.hostname,
            "last_latency_ms": device.latency_ms,
            "open_ports": device.open_ports,
            "last_seen": device.last_seen,
            "updated_at": now,
        })
        record.setdefault("first_seen", device.last_seen)
        record.setdefault("category", "")
        record.setdefault("owner", "")
        record.setdefault("location", "")
        record.setdefault("notes", "")
        record["seen_count"] = int(record.get("seen_count", 0)) + 1
        records[key] = record

    save_inventory(inventory)


def inventory_list() -> list[dict]:
    records = load_inventory().get("devices", {})
    return sorted(records.values(), key=lambda item: (item.get("device_name") or item.get("ip") or ""))


def update_inventory_item(payload: dict) -> dict:
    ip = str(payload.get("ip", "")).strip()
    mac = str(payload.get("mac", "")).strip().upper() or None
    key = str(payload.get("key", "")).strip() or inventory_key(ip, mac)

    if not ip:
        raise ValueError("IP-адрес обязателен.")
    ipaddress.ip_address(ip)

    allowed = {"device_name", "category", "owner", "location", "notes", "status"}
    inventory = load_inventory()
    records = inventory.setdefault("devices", {})
    record = records.get(key) or {"key": key, "ip": ip, "mac": mac, "first_seen": datetime.now().isoformat(timespec="seconds"), "seen_count": 0}

    record["ip"] = ip
    record["mac"] = mac
    for field in allowed:
        if field in payload:
            value = str(payload.get(field, "")).strip()
            if len(value) > 500:
                raise ValueError(f"Поле {field} слишком длинное.")
            record[field] = value

    record["updated_at"] = datetime.now().isoformat(timespec="seconds")
    records[key] = record
    save_inventory(inventory)
    return record


def choose_device_name(ip: str, mac: str | None, hostname: str | None, netbios_name: str | None, names: dict) -> tuple[str | None, str | None]:
    by_ip = names.get("by_ip", {})
    by_mac = names.get("by_mac", {})

    if ip in by_ip and by_ip[ip].strip():
        return by_ip[ip].strip(), "manual_ip"
    if mac and mac in by_mac and by_mac[mac].strip():
        return by_mac[mac].strip(), "manual_mac"
    if netbios_name:
        return netbios_name, "netbios"
    if hostname:
        return hostname.split(".")[0], "dns"
    return None, None


def guess_local_cidr() -> str:
    candidates: list[str] = []
    try:
        host = socket.gethostname()
        candidates.extend(socket.gethostbyname_ex(host)[2])
    except OSError:
        pass

    for ip in candidates:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if address.version == 4 and address.is_private and not address.is_loopback:
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(network)

    return "192.168.1.0/24"


def read_json_body(handler: SimpleHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    return json.loads(handler.rfile.read(length) or b"{}")


def run_command(command: list[str], timeout: int = 12) -> dict:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        output = (completed.stdout or completed.stderr or "").strip()
        return {
            "ok": completed.returncode == 0,
            "returnCode": completed.returncode,
            "command": " ".join(command),
            "output": output[:MAX_TOOL_OUTPUT],
        }
    except FileNotFoundError:
        return {"ok": False, "returnCode": None, "command": " ".join(command), "output": "Команда не найдена."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "returnCode": None, "command": " ".join(command), "output": "Команда превысила лимит времени."}


def validate_host(value: str) -> str:
    host = value.strip()
    if not host:
        raise ValueError("Укажите хост или IP-адрес.")
    if len(host) > 253:
        raise ValueError("Слишком длинное имя хоста.")
    if not re.fullmatch(r"[A-Za-z0-9А-Яа-яёЁ._:-]+", host):
        raise ValueError("Хост содержит недопустимые символы.")
    return host


def parse_ports(raw_ports: str | Iterable[int] | None) -> list[int]:
    if raw_ports is None or raw_ports == "":
        return DEFAULT_PORTS

    if isinstance(raw_ports, str):
        pieces = re.split(r"[\s,;]+", raw_ports.strip())
        ports = [int(piece) for piece in pieces if piece]
    else:
        ports = [int(port) for port in raw_ports]

    unique = sorted({port for port in ports if 1 <= port <= 65535})
    if not unique:
        raise ValueError("Нужно указать хотя бы один TCP-порт от 1 до 65535.")
    return unique


def validate_network(cidr: str, allow_public: bool) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Некорректный CIDR-диапазон: {cidr}") from exc

    if network.version != 4:
        raise ValueError("Поддерживаются только IPv4-диапазоны.")

    if network.num_addresses > MAX_HOSTS:
        raise ValueError(f"Диапазон слишком большой: {network.num_addresses} адресов. Максимум: {MAX_HOSTS}.")

    if not allow_public and not (network.is_private or network.is_loopback):
        raise ValueError("По умолчанию можно сканировать только приватные сети. Включите allowPublic осознанно.")

    return network


async def ping_host(ip: str, timeout_ms: int) -> float | None:
    is_windows = platform.system().lower().startswith("win")
    if is_windows:
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        timeout_seconds = max(1.0, timeout_ms / 1000 + 0.5)
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), ip]
        timeout_seconds = max(1.0, timeout_ms / 1000 + 0.5)

    started = time.perf_counter()
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return None

    if proc.returncode == 0:
        return round((time.perf_counter() - started) * 1000, 1)
    return None


async def check_port(ip: str, port: int, timeout_ms: int) -> bool:
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout_ms / 1000)
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def reverse_dns(ip: str) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        hostname, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return hostname
    except OSError:
        return None


def get_mac_from_arp(ip: str) -> str | None:
    try:
        output = subprocess.check_output(["arp", "-a", ip], text=True, stderr=subprocess.DEVNULL, timeout=2)
    except (OSError, subprocess.SubprocessError):
        return None

    match = re.search(r"(?i)([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", output)
    if not match:
        return None
    return match.group(0).replace("-", ":").upper()


def get_netbios_name(ip: str) -> str | None:
    if not platform.system().lower().startswith("win"):
        return None

    try:
        output = subprocess.check_output(["nbtstat", "-A", ip], text=True, stderr=subprocess.DEVNULL, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None

    for line in output.splitlines():
        if "<00>" not in line or "UNIQUE" not in line.upper():
            continue
        name = line.split("<00>", 1)[0].strip()
        if name and not name.startswith("__"):
            return name
    return None


async def scan_one(ip: str, ports: list[int], timeout_ms: int, semaphore: asyncio.Semaphore, names: dict) -> Device | None:
    async with semaphore:
        latency = await ping_host(ip, timeout_ms)
        open_checks = await asyncio.gather(*(check_port(ip, port, timeout_ms) for port in ports))
        open_ports = [port for port, is_open in zip(ports, open_checks) if is_open]

        if latency is None and not open_ports:
            return None

        hostname, mac, netbios_name = await asyncio.gather(
            reverse_dns(ip),
            asyncio.to_thread(get_mac_from_arp, ip),
            asyncio.to_thread(get_netbios_name, ip),
        )
        device_name, name_source = choose_device_name(ip, mac, hostname, netbios_name, names)
        return Device(
            ip=ip,
            device_name=device_name,
            name_source=name_source,
            hostname=hostname,
            mac=mac,
            latency_ms=latency,
            open_ports=open_ports,
            last_seen=datetime.now().isoformat(timespec="seconds"),
        )


async def scan_network(cidr: str, ports: list[int], timeout_ms: int, concurrency: int, allow_public: bool) -> dict:
    network = validate_network(cidr, allow_public)
    hosts = [str(ip) for ip in network.hosts()]
    semaphore = asyncio.Semaphore(max(1, min(concurrency, 256)))
    names = load_device_names()

    started = time.perf_counter()
    results = await asyncio.gather(*(scan_one(ip, ports, timeout_ms, semaphore, names) for ip in hosts))
    devices = sorted((device for device in results if device), key=lambda item: ipaddress.ip_address(item.ip))
    merge_scan_into_inventory(devices)
    result = {
        "cidr": str(network),
        "hostCount": len(hosts),
        "activeCount": len(devices),
        "durationSeconds": round(time.perf_counter() - started, 2),
        "scannedAt": datetime.now().isoformat(timespec="seconds"),
        "ports": ports,
        "devices": [asdict(device) for device in devices],
    }
    append_scan_history(result)
    return result


async def check_ports_for_host(host: str, ports: list[int], timeout_ms: int = 900) -> list[dict]:
    async def check(port: int) -> dict:
        is_open = await check_port(host, port, timeout_ms)
        return {"port": port, "state": "open" if is_open else "closed"}

    return await asyncio.gather(*(check(port) for port in ports))


def tool_ping(host: str, count: int = 4) -> dict:
    safe_host = validate_host(host)
    count = max(1, min(int(count), 10))
    if platform.system().lower().startswith("win"):
        command = ["ping", "-n", str(count), safe_host]
    else:
        command = ["ping", "-c", str(count), safe_host]
    return run_command(command, timeout=max(8, count * 3))


def tool_trace(host: str) -> dict:
    safe_host = validate_host(host)
    if platform.system().lower().startswith("win"):
        command = ["tracert", "-d", "-h", "16", safe_host]
    else:
        command = ["traceroute", "-n", "-m", "16", safe_host]
    return run_command(command, timeout=25)


def tool_dns(host: str) -> dict:
    safe_host = validate_host(host)
    addresses: list[str] = []
    reverse: str | None = None
    error: str | None = None

    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(safe_host, None):
            if family in (socket.AF_INET, socket.AF_INET6):
                addresses.append(sockaddr[0])
    except OSError as exc:
        error = str(exc)

    try:
        reverse = socket.gethostbyaddr(safe_host)[0]
    except OSError:
        reverse = None

    return {
        "host": safe_host,
        "addresses": sorted(set(addresses)),
        "reverse": reverse,
        "error": error,
    }


def tool_subnet(cidr: str) -> dict:
    network = validate_network(cidr, allow_public=False)
    hosts = list(network.hosts())
    return {
        "cidr": str(network),
        "network": str(network.network_address),
        "broadcast": str(network.broadcast_address),
        "netmask": str(network.netmask),
        "wildcard": str(network.hostmask),
        "prefixLength": network.prefixlen,
        "totalAddresses": network.num_addresses,
        "usableHosts": len(hosts),
        "firstHost": str(hosts[0]) if hosts else None,
        "lastHost": str(hosts[-1]) if hosts else None,
        "isPrivate": network.is_private,
    }


def parse_arp_table() -> list[dict]:
    result = run_command(["arp", "-a"], timeout=8)
    rows: list[dict] = []
    if not result["output"]:
        return rows

    for line in result["output"].splitlines():
        match = re.search(r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})\s+(?P<kind>\S+)", line)
        if match:
            rows.append({
                "ip": match.group("ip"),
                "mac": match.group("mac").replace("-", ":").upper(),
                "type": match.group("kind"),
            })
    return rows


def local_system_info() -> dict:
    addresses: list[dict] = []
    try:
        hostname = socket.gethostname()
        for ip in sorted(set(socket.gethostbyname_ex(hostname)[2])):
            address = ipaddress.ip_address(ip)
            addresses.append({"ip": ip, "isPrivate": address.is_private, "isLoopback": address.is_loopback})
    except OSError:
        hostname = socket.gethostname()

    return {
        "hostname": hostname,
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "addresses": addresses,
        "arp": parse_arp_table(),
    }


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/defaults":
            self.send_json({"cidr": guess_local_cidr(), "ports": DEFAULT_PORTS})
            return
        if parsed.path == "/api/names":
            self.send_json(load_device_names())
            return
        if parsed.path == "/api/inventory":
            self.send_json({"devices": inventory_list()})
            return
        if parsed.path == "/api/history":
            self.send_json(load_history())
            return
        if parsed.path == "/api/profiles":
            self.send_json(load_profiles())
            return
        if parsed.path == "/api/tools/system":
            self.send_json(local_system_info())
            return
        if parsed.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        if parsed.path == "/":
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/device-name":
            self.save_device_name()
            return
        if parsed.path == "/api/inventory-item":
            self.save_inventory_item()
            return
        if parsed.path == "/api/history-clear":
            clear_history()
            self.send_json({"ok": True, "scans": []})
            return
        if parsed.path == "/api/profile":
            self.save_profile()
            return
        if parsed.path == "/api/profile-delete":
            payload = read_json_body(self)
            self.send_json(delete_profile(str(payload.get("id", "")).strip()))
            return
        if parsed.path.startswith("/api/tools/"):
            self.run_tool(parsed.path.rsplit("/", 1)[-1])
            return
        if parsed.path != "/api/scan":
            self.send_error(404)
            return

        try:
            payload = read_json_body(self)
            cidr = str(payload.get("cidr", "")).strip()
            ports = parse_ports(payload.get("ports"))
            timeout_ms = int(payload.get("timeoutMs", 700))
            concurrency = int(payload.get("concurrency", 96))
            allow_public = bool(payload.get("allowPublic", False))

            if not cidr:
                raise ValueError("Укажите CIDR-диапазон, например 192.168.1.0/24.")
            if not 100 <= timeout_ms <= 5000:
                raise ValueError("Таймаут должен быть от 100 до 5000 мс.")

            result = asyncio.run(scan_network(cidr, ports, timeout_ms, concurrency, allow_public))
            self.send_json(result)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            self.send_json({"error": f"Ошибка сканирования: {exc}"}, status=500)

    def save_device_name(self) -> None:
        try:
            payload = read_json_body(self)
            ip = str(payload.get("ip", "")).strip()
            mac = str(payload.get("mac", "")).strip().upper()
            name = str(payload.get("name", "")).strip()

            if not ip:
                raise ValueError("IP-адрес обязателен.")
            ipaddress.ip_address(ip)
            if len(name) > 80:
                raise ValueError("Название устройства должно быть не длиннее 80 символов.")

            names = load_device_names()
            if name:
                names.setdefault("by_ip", {})[ip] = name
                if mac:
                    names.setdefault("by_mac", {})[mac] = name
            else:
                names.setdefault("by_ip", {}).pop(ip, None)
                if mac:
                    names.setdefault("by_mac", {}).pop(mac, None)

            save_device_names(names)
            if name:
                update_inventory_item({"ip": ip, "mac": mac, "device_name": name})
            self.send_json({"ok": True, "names": names})
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            self.send_json({"error": f"Не удалось сохранить название устройства: {exc}"}, status=500)

    def save_inventory_item(self) -> None:
        try:
            record = update_inventory_item(read_json_body(self))
            self.send_json({"ok": True, "device": record})
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            self.send_json({"error": f"Не удалось сохранить карточку: {exc}"}, status=500)

    def save_profile(self) -> None:
        try:
            profile = upsert_profile(read_json_body(self))
            self.send_json({"ok": True, "profile": profile, "profiles": load_profiles().get("profiles", [])})
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            self.send_json({"error": f"Не удалось сохранить профиль: {exc}"}, status=500)

    def run_tool(self, tool_name: str) -> None:
        try:
            payload = read_json_body(self)

            if tool_name == "ping":
                self.send_json(tool_ping(str(payload.get("host", "")), int(payload.get("count", 4))))
                return
            if tool_name == "trace":
                self.send_json(tool_trace(str(payload.get("host", ""))))
                return
            if tool_name == "dns":
                self.send_json(tool_dns(str(payload.get("host", ""))))
                return
            if tool_name == "ports":
                host = validate_host(str(payload.get("host", "")))
                ports = parse_ports(payload.get("ports"))
                result = asyncio.run(check_ports_for_host(host, ports, int(payload.get("timeoutMs", 900))))
                self.send_json({"host": host, "ports": result})
                return
            if tool_name == "subnet":
                self.send_json(tool_subnet(str(payload.get("cidr", ""))))
                return
            if tool_name == "arp":
                self.send_json({"rows": parse_arp_table()})
                return

            self.send_error(404)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            self.send_json({"error": f"Ошибка инструмента: {exc}"}, status=500)

    def send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        if os.environ.get("SCANNER_DEBUG"):
            super().log_message(format, *args)


def main() -> None:
    parser = argparse.ArgumentParser(description="Office network scanner")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Office Network Scanner: http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
