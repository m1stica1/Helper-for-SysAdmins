const state = {
  lastResult: null,
  scanning: false,
};

const viewMeta = {
  scanner: ["Сканирование сети", "Инвентаризация активных IP-адресов в офисном LAN."],
  diagnostics: ["Диагностика", "Ping, трассировка, DNS и проверка TCP-портов."],
  subnet: ["Подсети", "Расчет адресного пространства и маски сети."],
  system: ["Система", "Локальные адреса и ARP-таблица."],
  handbook: ["Справочник", "Быстрые команды для работы администратора."],
};

const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function updateClock() {
  $("clock").textContent = new Intl.DateTimeFormat("ru-RU", {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(new Date());
}

function showView(view) {
  document.querySelectorAll(".view").forEach((node) => node.classList.remove("active"));
  document.querySelectorAll("nav a").forEach((node) => node.classList.remove("active"));

  $(`${view}View`).classList.add("active");
  document.querySelector(`nav a[data-view="${view}"]`).classList.add("active");
  $("pageTitle").textContent = viewMeta[view][0];
  $("pageSubtitle").textContent = viewMeta[view][1];

  if (view === "system" && !$("systemOutput").textContent.trim()) {
    loadSystem();
  }
}

function prettyJson(data) {
  return JSON.stringify(data, null, 2);
}

function setOutput(id, value) {
  $(id).textContent = typeof value === "string" ? value : prettyJson(value);
}

async function postTool(tool, payload) {
  const response = await fetch(`/api/tools/${tool}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Ошибка выполнения.");
  return data;
}

function setScanning(scanning) {
  state.scanning = scanning;
  $("scanBtn").disabled = scanning;
  $("refreshBtn").disabled = scanning;
  $("scanBtn").textContent = scanning ? "Сканирование..." : "▶ Сканировать";
}

function formatDate(value) {
  if (!value) return "-";
  return new Intl.DateTimeFormat("ru-RU", {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(new Date(value));
}

function renderResult(result) {
  state.lastResult = result;
  const devices = result.devices || [];
  const openPortCount = devices.reduce((sum, item) => sum + item.open_ports.length, 0);
  const completion = result.hostCount ? Math.round((devices.length / result.hostCount) * 100) : 0;

  $("activeCount").textContent = devices.length;
  $("hostCount").textContent = result.hostCount || 0;
  $("openPortCount").textContent = openPortCount;
  $("duration").textContent = `${result.durationSeconds || 0} c`;
  $("scanTitle").textContent = `Сканирование ${result.cidr}`;
  $("scanMeta").textContent = `Активных устройств: ${devices.length}. Проверено адресов: ${result.hostCount}.`;
  $("scanError").textContent = "";
  $("ring").style.background = `conic-gradient(var(--teal) ${Math.max(completion, 6) * 3.6}deg, var(--line) 0deg)`;

  const body = $("devices");
  if (!devices.length) {
    body.innerHTML = '<tr><td colspan="8" class="empty">Активные устройства не найдены</td></tr>';
    return;
  }

  body.innerHTML = devices
    .map((device) => {
      const ports = device.open_ports.length ? device.open_ports.map((port) => `${port}/tcp`).join(", ") : "-";
      const latency = device.latency_ms === null ? "-" : `${device.latency_ms} мс`;
      const nameSource = {
        manual_ip: "закреплено за IP",
        manual_mac: "закреплено за MAC",
        netbios: "NetBIOS",
        dns: "DNS",
      }[device.name_source] || "нет имени";
      return `
        <tr>
          <td><span class="state">online</span></td>
          <td><strong>${escapeHtml(device.ip)}</strong></td>
          <td>
            <div class="name-cell">
              <input
                class="device-name-input"
                data-ip="${escapeHtml(device.ip)}"
                data-mac="${escapeHtml(device.mac || "")}"
                value="${escapeHtml(device.device_name || "")}"
                placeholder="Например: Принтер бухгалтерии"
              />
              <button class="save-name-btn" type="button" data-ip="${escapeHtml(device.ip)}" data-mac="${escapeHtml(device.mac || "")}">✓</button>
            </div>
            <small class="name-source">${escapeHtml(nameSource)}</small>
          </td>
          <td>${escapeHtml(device.hostname || "-")}</td>
          <td>${escapeHtml(device.mac || "-")}</td>
          <td>${ports}</td>
          <td>${latency}</td>
          <td>${formatDate(device.last_seen)}</td>
        </tr>
      `;
    })
    .join("");
}

async function saveDeviceName(button) {
  const ip = button.dataset.ip;
  const mac = button.dataset.mac;
  const input = document.querySelector(`.device-name-input[data-ip="${CSS.escape(ip)}"]`);
  if (!input) return;

  button.disabled = true;
  try {
    const response = await fetch("/api/device-name", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, mac, name: input.value.trim() }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Не удалось сохранить название.");

    if (state.lastResult) {
      const device = state.lastResult.devices.find((item) => item.ip === ip);
      if (device) {
        device.device_name = input.value.trim() || null;
        device.name_source = input.value.trim() ? "manual_ip" : null;
      }
      renderResult(state.lastResult);
    }
  } catch (error) {
    $("scanError").textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function runScan() {
  if (state.scanning) return;

  setScanning(true);
  $("scanTitle").textContent = "Идет сканирование";
  $("scanMeta").textContent = "Проверка может занять до нескольких минут.";
  $("scanError").textContent = "";

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        cidr: $("cidr").value.trim(),
        ports: $("ports").value.trim(),
        timeoutMs: Number($("timeout").value),
        concurrency: Number($("concurrency").value),
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Не удалось выполнить сканирование.");
    renderResult(data);
  } catch (error) {
    $("scanTitle").textContent = "Ошибка";
    $("scanMeta").textContent = "Сканирование не выполнено.";
    $("scanError").textContent = error.message;
  } finally {
    setScanning(false);
  }
}

function download(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function exportJson() {
  if (!state.lastResult) return;
  download("network-scan.json", JSON.stringify(state.lastResult, null, 2), "application/json");
}

function exportCsv() {
  if (!state.lastResult) return;
  const rows = [["ip", "device_name", "name_source", "hostname", "mac", "open_ports", "latency_ms", "last_seen"]];
  for (const device of state.lastResult.devices) {
    rows.push([
      device.ip,
      device.device_name || "",
      device.name_source || "",
      device.hostname || "",
      device.mac || "",
      device.open_ports.join(" "),
      device.latency_ms ?? "",
      device.last_seen,
    ]);
  }
  const csv = rows
    .map((row) => row.map((cell) => `"${String(cell).replaceAll('"', '""')}"`).join(","))
    .join("\n");
  download("network-scan.csv", csv, "text/csv;charset=utf-8");
}

async function loadDefaults() {
  const response = await fetch("/api/defaults");
  const data = await response.json();
  $("cidr").value = data.cidr;
  $("ports").value = data.ports.join(", ");
  $("pingHost").value = data.cidr.split("/")[0].replace(/\.0$/, ".1");
  $("traceHost").value = $("pingHost").value;
  $("portHost").value = $("pingHost").value;
  $("subnetCidr").value = data.cidr;
}

async function runTool(outputId, tool, payload) {
  setOutput(outputId, "Выполняется...");
  try {
    const data = await postTool(tool, payload);
    if ("output" in data) {
      setOutput(outputId, data.output || "(нет вывода)");
    } else {
      setOutput(outputId, data);
    }
  } catch (error) {
    setOutput(outputId, error.message);
  }
}

async function loadSystem() {
  setOutput("systemOutput", "Загрузка...");
  try {
    const response = await fetch("/api/tools/system");
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Ошибка загрузки.");
    setOutput("systemOutput", data);
  } catch (error) {
    setOutput("systemOutput", error.message);
  }
}

async function loadArp() {
  await runTool("systemOutput", "arp", {});
}

$("scanBtn").addEventListener("click", runScan);
$("refreshBtn").addEventListener("click", runScan);
$("csvBtn").addEventListener("click", exportCsv);
$("jsonBtn").addEventListener("click", exportJson);
document.querySelectorAll("nav a[data-view]").forEach((link) => {
  link.addEventListener("click", (event) => {
    event.preventDefault();
    showView(link.dataset.view);
  });
});
$("devices").addEventListener("click", (event) => {
  const button = event.target.closest(".save-name-btn");
  if (button) saveDeviceName(button);
});
$("devices").addEventListener("keydown", (event) => {
  if (event.key !== "Enter" || !event.target.classList.contains("device-name-input")) return;
  const input = event.target;
  const button = document.querySelector(`.save-name-btn[data-ip="${CSS.escape(input.dataset.ip)}"]`);
  if (button) saveDeviceName(button);
});
$("pingBtn").addEventListener("click", () => runTool("pingOutput", "ping", {
  host: $("pingHost").value,
  count: Number($("pingCount").value),
}));
$("traceBtn").addEventListener("click", () => runTool("traceOutput", "trace", {
  host: $("traceHost").value,
}));
$("dnsBtn").addEventListener("click", () => runTool("dnsOutput", "dns", {
  host: $("dnsHost").value,
}));
$("portBtn").addEventListener("click", () => runTool("portOutput", "ports", {
  host: $("portHost").value,
  ports: $("portList").value,
}));
$("subnetBtn").addEventListener("click", () => runTool("subnetOutput", "subnet", {
  cidr: $("subnetCidr").value,
}));
$("systemBtn").addEventListener("click", loadSystem);
$("arpBtn").addEventListener("click", loadArp);

updateClock();
setInterval(updateClock, 1000);
loadDefaults();
