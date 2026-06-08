const state = {
  lastResult: null,
  inventory: [],
  scanning: false,
};

const viewMeta = {
  scanner: ["Сканирование сети", "Инвентаризация активных IP-адресов в офисном LAN."],
  inventory: ["Инвентарь", "Постоянная база устройств с ответственными, локациями и заметками."],
  diagnostics: ["Диагностика", "Ping, трассировка, DNS и проверка TCP-портов."],
  subnet: ["Подсети", "Расчет адресного пространства и маски сети."],
  system: ["Система", "Локальные адреса и ARP-таблица."],
  handbook: ["Справочник", "Быстрые команды для работы администратора."],
};

const $ = (id) => document.getElementById(id);

function applyTheme(theme) {
  const nextTheme = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = nextTheme;
  localStorage.setItem("helper-theme", nextTheme);
  $("themeToggleText").textContent = nextTheme === "dark" ? "Темная" : "Светлая";
  $("themeToggle").setAttribute("aria-pressed", String(nextTheme === "dark"));
}

function initTheme() {
  applyTheme(localStorage.getItem("helper-theme") || "dark");
}

function toggleTheme() {
  const current = document.documentElement.dataset.theme || "dark";
  applyTheme(current === "dark" ? "light" : "dark");
}

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
  if (view === "inventory") {
    loadInventory();
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

function getFilteredScanDevices() {
  const result = state.lastResult;
  if (!result) return [];

  const text = $("scanFilterText").value.trim().toLowerCase();
  const port = Number($("scanFilterPort").value);
  const mode = $("scanFilterMode").value;

  return (result.devices || []).filter((device) => {
    const haystack = [
      device.ip,
      device.device_name,
      device.hostname,
      device.mac,
      device.name_source,
      ...(device.open_ports || []),
    ].join(" ").toLowerCase();
    const textMatch = !text || haystack.includes(text);
    const portMatch = !port || (device.open_ports || []).includes(port);
    const modeMatch =
      mode === "all" ||
      (mode === "withPorts" && (device.open_ports || []).length > 0) ||
      (mode === "named" && device.device_name) ||
      (mode === "unnamed" && !device.device_name);
    return textMatch && portMatch && modeMatch;
  });
}

function renderResult(result) {
  state.lastResult = result;
  const allDevices = result.devices || [];
  const devices = getFilteredScanDevices();
  const openPortCount = allDevices.reduce((sum, item) => sum + item.open_ports.length, 0);
  const completion = result.hostCount ? Math.round((allDevices.length / result.hostCount) * 100) : 0;

  $("activeCount").textContent = allDevices.length;
  $("hostCount").textContent = result.hostCount || 0;
  $("openPortCount").textContent = openPortCount;
  $("duration").textContent = `${result.durationSeconds || 0} c`;
  $("scanTitle").textContent = `Сканирование ${result.cidr}`;
  $("scanMeta").textContent = `Активных устройств: ${allDevices.length}. Проверено адресов: ${result.hostCount}.`;
  $("scanFilterCount").textContent = `${devices.length} из ${allDevices.length} устройств`;
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
    loadInventory();
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
  for (const device of getFilteredScanDevices()) {
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

function renderInventory() {
  const query = $("inventorySearch").value.trim().toLowerCase();
  const statusFilter = $("inventoryStatusFilter").value;
  const categoryFilter = $("inventoryCategoryFilter").value.trim().toLowerCase();
  const ownerFilter = $("inventoryOwnerFilter").value.trim().toLowerCase();
  const locationFilter = $("inventoryLocationFilter").value.trim().toLowerCase();

  const devices = state.inventory.filter((device) => {
    const haystack = [
      device.ip,
      device.mac,
      device.device_name,
      device.hostname,
      device.category,
      device.owner,
      device.location,
      device.status,
      device.notes,
    ].join(" ").toLowerCase();
    const status = (device.status || "").toLowerCase();
    const statusMatch =
      !statusFilter ||
      (statusFilter === "empty" && !status) ||
      status === statusFilter;
    const categoryMatch = !categoryFilter || String(device.category || "").toLowerCase().includes(categoryFilter);
    const ownerMatch = !ownerFilter || String(device.owner || "").toLowerCase().includes(ownerFilter);
    const locationMatch = !locationFilter || String(device.location || "").toLowerCase().includes(locationFilter);
    return (!query || haystack.includes(query)) && statusMatch && categoryMatch && ownerMatch && locationMatch;
  });

  $("inventoryCount").textContent = `${devices.length} устройств`;
  const body = $("inventoryRows");
  if (!devices.length) {
    body.innerHTML = '<tr><td colspan="8" class="empty">Устройства не найдены</td></tr>';
    return;
  }

  body.innerHTML = devices.map((device) => `
    <tr data-key="${escapeHtml(device.key || "")}">
      <td>
        <input class="inventory-field strong-field" data-field="device_name" value="${escapeHtml(device.device_name || "")}" placeholder="Название" />
        <small>${escapeHtml(device.hostname || "hostname не определен")}</small>
      </td>
      <td>
        <strong>${escapeHtml(device.ip || "-")}</strong>
        <small>${escapeHtml(device.mac || "MAC не определен")}</small>
      </td>
      <td><input class="inventory-field" data-field="category" value="${escapeHtml(device.category || "")}" placeholder="ПК, принтер..." /></td>
      <td><input class="inventory-field" data-field="owner" value="${escapeHtml(device.owner || "")}" placeholder="Ответственный" /></td>
      <td><input class="inventory-field" data-field="location" value="${escapeHtml(device.location || "")}" placeholder="Кабинет" /></td>
      <td>
        <select class="inventory-field" data-field="status">
          ${["", "active", "reserved", "maintenance", "retired"].map((status) => `
            <option value="${status}" ${device.status === status ? "selected" : ""}>${status || "не задан"}</option>
          `).join("")}
        </select>
      </td>
      <td><textarea class="inventory-field notes-field" data-field="notes" placeholder="Заметки">${escapeHtml(device.notes || "")}</textarea></td>
      <td>
        <button class="save-inventory-btn primary" type="button">Сохранить</button>
        <small>Первый раз: ${escapeHtml(formatDate(device.first_seen))}</small>
        <small>Последний раз: ${escapeHtml(formatDate(device.last_seen))}</small>
        <small>Обнаружений: ${escapeHtml(device.seen_count || 0)}</small>
      </td>
    </tr>
  `).join("");
}

async function loadInventory() {
  try {
    const response = await fetch("/api/inventory");
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Не удалось загрузить инвентарь.");
    state.inventory = data.devices || [];
    renderInventory();
  } catch (error) {
    $("inventoryRows").innerHTML = `<tr><td colspan="8" class="empty">${escapeHtml(error.message)}</td></tr>`;
  }
}

async function saveInventoryRow(button) {
  const row = button.closest("tr");
  const key = row.dataset.key;
  const device = state.inventory.find((item) => item.key === key);
  if (!device) return;

  const payload = {
    key,
    ip: device.ip,
    mac: device.mac,
  };
  row.querySelectorAll(".inventory-field").forEach((field) => {
    payload[field.dataset.field] = field.value;
  });

  button.disabled = true;
  try {
    const response = await fetch("/api/inventory-item", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Не удалось сохранить карточку.");
    const index = state.inventory.findIndex((item) => item.key === key);
    if (index >= 0) state.inventory[index] = data.device;
    renderInventory();
  } catch (error) {
    alert(error.message);
  } finally {
    button.disabled = false;
  }
}

function exportInventory() {
  download("inventory.json", JSON.stringify({ devices: state.inventory }, null, 2), "application/json");
}

function resetScanFilters() {
  $("scanFilterText").value = "";
  $("scanFilterPort").value = "";
  $("scanFilterMode").value = "all";
  if (state.lastResult) renderResult(state.lastResult);
}

function resetInventoryFilters() {
  $("inventorySearch").value = "";
  $("inventoryStatusFilter").value = "";
  $("inventoryCategoryFilter").value = "";
  $("inventoryOwnerFilter").value = "";
  $("inventoryLocationFilter").value = "";
  renderInventory();
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
$("scanFilterText").addEventListener("input", () => state.lastResult && renderResult(state.lastResult));
$("scanFilterPort").addEventListener("input", () => state.lastResult && renderResult(state.lastResult));
$("scanFilterMode").addEventListener("change", () => state.lastResult && renderResult(state.lastResult));
$("scanFilterResetBtn").addEventListener("click", resetScanFilters);
$("inventoryRefreshBtn").addEventListener("click", loadInventory);
$("inventoryExportBtn").addEventListener("click", exportInventory);
$("inventorySearch").addEventListener("input", renderInventory);
$("inventoryStatusFilter").addEventListener("change", renderInventory);
$("inventoryCategoryFilter").addEventListener("input", renderInventory);
$("inventoryOwnerFilter").addEventListener("input", renderInventory);
$("inventoryLocationFilter").addEventListener("input", renderInventory);
$("inventoryResetBtn").addEventListener("click", resetInventoryFilters);
$("inventoryRows").addEventListener("click", (event) => {
  const button = event.target.closest(".save-inventory-btn");
  if (button) saveInventoryRow(button);
});
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
$("themeToggle").addEventListener("click", toggleTheme);

initTheme();
updateClock();
setInterval(updateClock, 1000);
loadDefaults();
