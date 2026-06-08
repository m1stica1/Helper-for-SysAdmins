const state = {
  lastResult: null,
  inventory: [],
  history: [],
  profiles: [],
  scanning: false,
  selectedNeighborIps: new Set(),
  activeNeighborIp: null,
  scanSort: { key: "ip", dir: "asc" },
};

const viewMeta = {
  scanner: ["Сканирование сети", "Инвентаризация активных IP-адресов в офисном LAN."],
  inventory: ["Инвентарь", "Постоянная база устройств с ответственными, локациями и заметками."],
  history: ["Журнал", "История запусков сканирования и сохраненные снимки сети."],
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
  if (view === "history") {
    loadHistory();
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

async function postJson(url, payload) {
  const response = await fetch(url, {
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

function formatPorts(openPorts = []) {
  return openPorts.length ? openPorts.map((port) => `tcp/${port}`).join(", ") : "-";
}

function formatNeighborPort(device) {
  if (device.board_port) return device.board_port;
  return formatPorts(device.open_ports || []);
}

function ipSortValue(value) {
  const parts = String(value || "").split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) return 0;
  return parts.reduce((sum, part) => (sum * 256) + part, 0);
}

function deviceIdentity(device) {
  return device.device_name || device.hostname || "";
}

function sortDevices(devices) {
  const { key, dir } = state.scanSort;
  const direction = dir === "desc" ? -1 : 1;
  return [...devices].sort((left, right) => {
    if (key === "ip") return (ipSortValue(left.ip) - ipSortValue(right.ip)) * direction;
    const values = {
      mac: [left.mac || "", right.mac || ""],
      identity: [deviceIdentity(left), deviceIdentity(right)],
      version: [left.version || "", right.version || ""],
      board: [left.board || "", right.board || ""],
      uptime: [left.uptime || "", right.uptime || ""],
      port: [formatNeighborPort(left), formatNeighborPort(right)],
    }[key] || [left.ip || "", right.ip || ""];
    return values[0].localeCompare(values[1], "ru", { numeric: true, sensitivity: "base" }) * direction;
  });
}

function getFilteredScanDevices() {
  const result = state.lastResult;
  if (!result) return [];

  const text = $("scanFilterText").value.trim().toLowerCase();
  const port = Number($("scanFilterPort").value);
  const mode = $("scanFilterMode").value;

  const filtered = (result.devices || []).filter((device) => {
    const haystack = [
      device.ip,
      device.device_name,
      device.hostname,
      device.mac,
      device.name_source,
      device.version,
      device.board,
      device.board_port,
      device.uptime,
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
  return sortDevices(filtered);
}

function findDeviceByIp(ip) {
  return (state.lastResult?.devices || []).find((device) => device.ip === ip);
}

function selectedNeighborDevices() {
  return [...state.selectedNeighborIps]
    .map((ip) => findDeviceByIp(ip))
    .filter(Boolean);
}

function updateSortHeaders() {
  document.querySelectorAll(".sort-header").forEach((button) => {
    const active = button.dataset.sort === state.scanSort.key;
    button.classList.toggle("sorted", active);
    button.classList.toggle("desc", active && state.scanSort.dir === "desc");
  });
}

function updateNeighborSelectionUi() {
  const visibleDevices = getFilteredScanDevices();
  const visibleIps = new Set(visibleDevices.map((device) => device.ip));
  for (const ip of [...state.selectedNeighborIps]) {
    if (!findDeviceByIp(ip)) state.selectedNeighborIps.delete(ip);
  }

  document.querySelectorAll("#devices tr[data-ip]").forEach((row) => {
    const selected = state.selectedNeighborIps.has(row.dataset.ip);
    row.classList.toggle("selected", selected);
    row.classList.toggle("active-neighbor", row.dataset.ip === state.activeNeighborIp);
    const checkbox = row.querySelector('input[type="checkbox"]');
    if (checkbox) checkbox.checked = selected;
  });

  const selectedVisibleCount = [...state.selectedNeighborIps].filter((ip) => visibleIps.has(ip)).length;
  const selectAll = $("neighborSelectAll");
  selectAll.disabled = visibleDevices.length === 0;
  selectAll.checked = visibleDevices.length > 0 && selectedVisibleCount === visibleDevices.length;
  selectAll.indeterminate = selectedVisibleCount > 0 && selectedVisibleCount < visibleDevices.length;

  const selectedCount = state.selectedNeighborIps.size;
  $("neighborSelectedCount").textContent = `${selectedCount} selected`;
  ["neighborInspectBtn", "neighborNameBtn", "neighborPingBtn", "neighborCopyBtn"].forEach((id) => {
    $(id).disabled = selectedCount === 0;
  });
}

function renderNeighborInspector(device) {
  if (!device) {
    $("neighborInspector").hidden = true;
    state.activeNeighborIp = null;
    updateNeighborSelectionUi();
    return;
  }

  state.activeNeighborIp = device.ip;
  $("neighborInspector").hidden = false;
  $("neighborInspectorTitle").textContent = deviceIdentity(device) || device.ip;
  $("neighborInspectorMeta").textContent = `${device.ip} · ${device.hostname || "hostname не найден"}`;
  $("neighborIdentityInput").value = device.device_name || "";
  $("neighborInspectorMac").textContent = device.mac || "-";
  $("neighborInspectorPorts").textContent = formatPorts(device.open_ports || []);
  $("neighborInspectorSeen").textContent = formatDate(device.last_seen);
  updateNeighborSelectionUi();
}

function renderResult(result) {
  state.lastResult = result;
  const allDevices = result.devices || [];
  const devices = getFilteredScanDevices();
  const openPortCount = allDevices.reduce((sum, item) => sum + (item.open_ports || []).length, 0);
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
  updateSortHeaders();

  const body = $("devices");
  if (!devices.length) {
    body.innerHTML = '<tr><td colspan="8" class="empty">Активные устройства не найдены</td></tr>';
    updateNeighborSelectionUi();
    return;
  }

  body.innerHTML = devices
    .map((device) => {
      const identity = device.device_name || device.hostname || "-";
      const identitySource = {
        manual_ip: "закреплено за IP",
        manual_mac: "закреплено за MAC",
        netbios: "NetBIOS",
        dns: "DNS",
      }[device.name_source] || "нет имени";
      const selectedClass = state.selectedNeighborIps.has(device.ip) ? " selected" : "";
      const activeClass = device.ip === state.activeNeighborIp ? " active-neighbor" : "";
      return `
        <tr data-ip="${escapeHtml(device.ip)}" class="${selectedClass}${activeClass}">
          <td class="neighbor-check-cell"><input type="checkbox" aria-label="Выбрать ${escapeHtml(device.ip)}" ${state.selectedNeighborIps.has(device.ip) ? "checked" : ""} /></td>
          <td>${escapeHtml(device.mac || "-")}</td>
          <td><strong>${escapeHtml(device.ip)}</strong></td>
          <td>
            <div class="identity-cell">
              <strong>${escapeHtml(identity)}</strong>
              <small>${escapeHtml(identitySource)}</small>
            </div>
          </td>
          <td>${escapeHtml(device.version || "-")}</td>
          <td>${escapeHtml(device.board || "-")}</td>
          <td class="neighbor-muted">${escapeHtml(device.uptime || "-")}</td>
          <td><span class="port-list">${escapeHtml(formatNeighborPort(device))}</span></td>
        </tr>
      `;
    })
    .join("");
  updateNeighborSelectionUi();
}

function renderProfiles() {
  const select = $("profileSelect");
  if (!state.profiles.length) {
    select.innerHTML = '<option value="">Нет профилей</option>';
    return;
  }

  select.innerHTML = state.profiles.map((profile) => `
    <option value="${escapeHtml(profile.id)}">${escapeHtml(profile.name)}</option>
  `).join("");

  if (!$("profileName").value && state.profiles[0]) {
    applyProfile(state.profiles[0].id);
  }
}

function selectedProfile() {
  return state.profiles.find((profile) => profile.id === $("profileSelect").value);
}

function applyProfile(profileId = $("profileSelect").value) {
  const profile = state.profiles.find((item) => item.id === profileId);
  if (!profile) return;
  $("profileSelect").value = profile.id;
  $("profileName").value = profile.name || "";
  $("cidr").value = profile.cidr || "";
  $("ports").value = (profile.ports || []).join(", ");
  $("timeout").value = profile.timeoutMs || 700;
  $("concurrency").value = profile.concurrency || 96;
}

async function loadProfiles() {
  try {
    const response = await fetch("/api/profiles");
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Не удалось загрузить профили.");
    state.profiles = data.profiles || [];
    renderProfiles();
  } catch (error) {
    $("scanError").textContent = error.message;
  }
}

async function saveCurrentProfile() {
  try {
    const current = selectedProfile();
    const data = await postJson("/api/profile", {
      id: current?.id || "",
      name: $("profileName").value.trim(),
      cidr: $("cidr").value.trim(),
      ports: $("ports").value.trim(),
      timeoutMs: Number($("timeout").value),
      concurrency: Number($("concurrency").value),
    });
    state.profiles = data.profiles || [];
    renderProfiles();
    $("profileSelect").value = data.profile.id;
    $("scanError").textContent = "";
  } catch (error) {
    $("scanError").textContent = error.message;
  }
}

async function deleteCurrentProfile() {
  const current = selectedProfile();
  if (!current) return;
  if (!confirm(`Удалить профиль "${current.name}"?`)) return;

  try {
    const data = await postJson("/api/profile-delete", { id: current.id });
    state.profiles = data.profiles || [];
    $("profileName").value = "";
    renderProfiles();
  } catch (error) {
    $("scanError").textContent = error.message;
  }
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

function firstSelectedNeighbor() {
  const devices = selectedNeighborDevices();
  return devices[0] || null;
}

function openSelectedNeighborInspector(focusIdentity = false) {
  const device = firstSelectedNeighbor();
  if (!device) return;
  renderNeighborInspector(device);
  if (focusIdentity) $("neighborIdentityInput").focus();
}

async function saveNeighborIdentity() {
  const device = state.activeNeighborIp ? findDeviceByIp(state.activeNeighborIp) : firstSelectedNeighbor();
  if (!device) return;

  const button = $("neighborSaveIdentityBtn");
  button.disabled = true;
  try {
    const name = $("neighborIdentityInput").value.trim();
    const response = await fetch("/api/device-name", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip: device.ip, mac: device.mac || "", name }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Не удалось сохранить Identity.");

    device.device_name = name || null;
    device.name_source = name ? "manual_ip" : null;
    renderResult(state.lastResult);
    renderNeighborInspector(device);
  } catch (error) {
    $("scanError").textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

function pingSelectedNeighbor() {
  const device = firstSelectedNeighbor();
  if (!device) return;
  $("pingHost").value = device.ip;
  showView("diagnostics");
  $("pingHost").focus();
}

async function copySelectedNeighbors() {
  const lines = selectedNeighborDevices().map((device) => [
    device.ip,
    device.mac || "-",
    deviceIdentity(device) || "-",
    formatNeighborPort(device),
  ].join("\t"));
  if (!lines.length) return;
  try {
    await navigator.clipboard.writeText(lines.join("\n"));
    $("neighborSelectedCount").textContent = `${lines.length} copied`;
  } catch (error) {
    $("scanError").textContent = "Не удалось скопировать в буфер обмена.";
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
    loadHistory();
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
  const rows = [["mac", "ip", "identity", "hostname", "version", "board", "uptime", "board_port", "open_ports", "latency_ms", "last_seen"]];
  for (const device of getFilteredScanDevices()) {
    rows.push([
      device.mac || "",
      device.ip || "",
      device.device_name || "",
      device.hostname || "",
      device.version || "",
      device.board || "",
      device.uptime || "",
      device.board_port || "",
      (device.open_ports || []).join(" "),
      device.latency_ms ?? "",
      device.last_seen || "",
    ]);
  }
  const csv = rows
    .map((row) => row.map((cell) => `"${String(cell).replaceAll('"', '""')}"`).join(","))
    .join("\n");
  download("network-neighbors.csv", csv, "text/csv;charset=utf-8");
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

function getFilteredHistory() {
  const query = $("historySearch").value.trim().toLowerCase();
  if (!query) return state.history;

  return state.history.filter((scan) => {
    const devices = scan.devices || [];
    const haystack = [
      scan.cidr,
      scan.scannedAt,
      scan.durationSeconds,
      scan.activeCount,
      scan.openPortTotal,
      ...(scan.ports || []),
      ...devices.flatMap((device) => [
        device.ip,
        device.device_name,
        device.hostname,
        device.mac,
        ...(device.open_ports || []),
      ]),
    ].join(" ").toLowerCase();
    return haystack.includes(query);
  });
}

function renderHistory() {
  const scans = getFilteredHistory();
  $("historyCount").textContent = `${scans.length} запусков`;

  const body = $("historyRows");
  if (!scans.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty">Запуски не найдены</td></tr>';
    $("historyDetails").textContent = "";
    return;
  }

  body.innerHTML = scans.map((scan) => `
    <tr>
      <td>${escapeHtml(formatDate(scan.scannedAt))}</td>
      <td><strong>${escapeHtml(scan.cidr || "-")}</strong><small>${escapeHtml((scan.ports || []).join(", "))}</small></td>
      <td>${escapeHtml(scan.activeCount || 0)} / ${escapeHtml(scan.hostCount || 0)}</td>
      <td>${escapeHtml(scan.openPortTotal || 0)}</td>
      <td>${escapeHtml(scan.durationSeconds || 0)} c</td>
      <td><button class="history-open-btn" type="button" data-id="${escapeHtml(scan.id)}">Открыть</button></td>
    </tr>
  `).join("");

  if (!$("historyDetails").textContent.trim()) {
    showHistoryDetails(scans[0].id);
  }
}

function showHistoryDetails(id) {
  const scan = state.history.find((item) => item.id === id);
  if (!scan) return;
  $("historyDetails").textContent = prettyJson(scan);
}

async function loadHistory() {
  try {
    const response = await fetch("/api/history");
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Не удалось загрузить журнал.");
    state.history = data.scans || [];
    renderHistory();
  } catch (error) {
    $("historyRows").innerHTML = `<tr><td colspan="6" class="empty">${escapeHtml(error.message)}</td></tr>`;
  }
}

function exportHistory() {
  download("scan-history.json", JSON.stringify({ scans: getFilteredHistory() }, null, 2), "application/json");
}

async function clearHistoryFromUi() {
  if (!confirm("Очистить журнал сканирований? Инвентарь устройств останется без изменений.")) return;

  const response = await fetch("/api/history-clear", { method: "POST" });
  const data = await response.json();
  if (!response.ok) {
    alert(data.error || "Не удалось очистить журнал.");
    return;
  }
  state.history = [];
  renderHistory();
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
$("profileSelect").addEventListener("change", () => applyProfile());
$("applyProfileBtn").addEventListener("click", () => applyProfile());
$("saveProfileBtn").addEventListener("click", saveCurrentProfile);
$("deleteProfileBtn").addEventListener("click", deleteCurrentProfile);
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
$("historyRefreshBtn").addEventListener("click", loadHistory);
$("historyExportBtn").addEventListener("click", exportHistory);
$("historyClearBtn").addEventListener("click", clearHistoryFromUi);
$("historySearch").addEventListener("input", renderHistory);
$("historyRows").addEventListener("click", (event) => {
  const button = event.target.closest(".history-open-btn");
  if (button) showHistoryDetails(button.dataset.id);
});
document.querySelectorAll("nav a[data-view]").forEach((link) => {
  link.addEventListener("click", (event) => {
    event.preventDefault();
    showView(link.dataset.view);
  });
});
$("devices").addEventListener("click", (event) => {
  const row = event.target.closest("tr[data-ip]");
  if (!row) return;

  if (event.target.matches('input[type="checkbox"]')) {
    if (event.target.checked) {
      state.selectedNeighborIps.add(row.dataset.ip);
    } else {
      state.selectedNeighborIps.delete(row.dataset.ip);
    }
    updateNeighborSelectionUi();
    return;
  }

  state.selectedNeighborIps.add(row.dataset.ip);
  renderNeighborInspector(findDeviceByIp(row.dataset.ip));
});
$("devices").addEventListener("keydown", (event) => {
  if (event.key !== "Enter") return;
  const row = event.target.closest("tr[data-ip]");
  if (row) renderNeighborInspector(findDeviceByIp(row.dataset.ip));
});
document.querySelectorAll(".sort-header").forEach((button) => {
  button.addEventListener("click", () => {
    const key = button.dataset.sort;
    state.scanSort = {
      key,
      dir: state.scanSort.key === key && state.scanSort.dir === "asc" ? "desc" : "asc",
    };
    if (state.lastResult) renderResult(state.lastResult);
  });
});
$("neighborSelectAll").addEventListener("change", (event) => {
  for (const device of getFilteredScanDevices()) {
    if (event.target.checked) {
      state.selectedNeighborIps.add(device.ip);
    } else {
      state.selectedNeighborIps.delete(device.ip);
    }
  }
  updateNeighborSelectionUi();
});
$("neighborInspectBtn").addEventListener("click", () => openSelectedNeighborInspector(false));
$("neighborNameBtn").addEventListener("click", () => openSelectedNeighborInspector(true));
$("neighborPingBtn").addEventListener("click", pingSelectedNeighbor);
$("neighborCopyBtn").addEventListener("click", copySelectedNeighbors);
$("neighborSaveIdentityBtn").addEventListener("click", saveNeighborIdentity);
$("neighborCloseInspectorBtn").addEventListener("click", () => renderNeighborInspector(null));
$("neighborIdentityInput").addEventListener("keydown", (event) => {
  if (event.key === "Enter") saveNeighborIdentity();
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
loadProfiles();
