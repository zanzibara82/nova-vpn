"use strict";

const stubMode = new URLSearchParams(location.search).get("stub") === "1";
const native = window.chrome && window.chrome.webview;
const bridge = native && !stubMode ? liveBridge(native) : stubBridge();

const state = {
  screen: null,
  appInfo: null,
  settings: null,
  session: null,
  me: null,
  devices: null,
  servers: [],
  profiles: [],
  diagnostics: null,
  currentDeviceId: null,
};

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function setText(id, text) {
  const node = $(id);
  if (node) node.textContent = text;
}

function setHiddenFor(action, hidden) {
  for (const node of document.querySelectorAll(`[data-action="${action}"]`)) node.hidden = hidden;
}

function fmtDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function fmtQuota(bytes) {
  if (bytes === null || bytes === undefined) return "без квоты";
  if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + " ГиБ";
  if (bytes >= 1048576) return Math.round(bytes / 1048576) + " МиБ";
  return bytes + " Б";
}

function profileStatus(status) {
  return {
    active: "активен",
    revoked: "отозван",
    expired: "истёк",
    replaced: "заменён",
  }[status] || status;
}

function profileStatusClass(status) {
  if (status === "active") return "badge badge-ok";
  if (status === "revoked" || status === "expired" || status === "replaced") return "badge badge-danger";
  return "badge badge-muted";
}

function availability(status) {
  if (status === "available") return "доступен";
  if (status === "unknown") return "неизвестно";
  return status;
}

function latency(value) {
  return value === null || value === undefined ? "не измерялось" : value + " мс";
}

function loadText(value) {
  return value === null || value === undefined ? "не заявлена" : "нагрузка " + value;
}

function capacity(value) {
  return value === null || value === undefined ? "не заявлена" : value + " Мбит/с";
}

function toast(message, kind) {
  const node = $("toast");
  node.textContent = message;
  node.className = "toast toast-" + (kind || "info");
  node.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { node.hidden = true; }, 6000);
}

function toastError(error) {
  const parts = [error.message || "Ошибка операции.", "код: " + (error.code || "internal")];
  if (error.requestId) parts.push("request_id: " + error.requestId);
  toast(parts.join(" · "), "error");
}

function liveBridge(webview) {
  let sequence = 0;
  const pending = new Map();
  webview.addEventListener("message", (event) => {
    const message = event.data;
    if (!message || typeof message.id !== "string") return;
    const entry = pending.get(message.id);
    if (!entry) return;
    pending.delete(message.id);
    clearTimeout(entry.timer);
    if (message.ok) {
      entry.resolve(message.data);
      return;
    }
    const error = message.error || {};
    entry.reject({
      code: error.code || "internal",
      message: error.message || "Ошибка операции.",
      requestId: error.request_id || null,
    });
  });
  return {
    mode: "live",
    send(command, args) {
      const id = "r" + (++sequence);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject({ code: "timeout", message: "Истекло время ожидания ответа приложения.", requestId: null });
        }, 60000);
        pending.set(id, { resolve, reject, timer });
        webview.postMessage({ id, command, args: args || {} });
      });
    },
  };
}

function stubBridge() {
  const device = {
    id: "22222222-2222-4222-8222-222222222222",
    public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    platform: "windows",
    name: "DEMO-WS",
    created_at: "2026-11-24T10:00:00Z",
    last_seen_at: null,
    revoked_at: null,
  };
  const servers = [
    {
      id: "33333333-3333-4333-8333-333333333333", name: "ams-1", country_code: "NL", city: "Амстердам",
      host: "203.0.113.10", port: 51820, mtu: 1420, latitude: 52.37, longitude: 4.89,
      availability: "available", latency_ms: null, load: null, capacity_mbps: null,
      provider: "demo", region: "eu-west",
    },
    {
      id: "44444444-4444-4444-8444-444444444444", name: "fra-2", country_code: "DE", city: "Франкфурт",
      host: "203.0.113.11", port: 51820, mtu: 1420, latitude: 50.11, longitude: 8.68,
      availability: "unknown", latency_ms: null, load: null, capacity_mbps: null,
      provider: "demo", region: "eu-central",
    },
  ];
  const events = [];
  let apiBaseUrl = "https://api.novavpn.test/";
  let email = null;
  let profiles = [];
  const note = (command, code) => events.unshift({
    time: new Date().toISOString(), command, code, request_id: null,
  });
  const fail = (code, message) => Promise.reject({ code, message, requestId: null });
  const me = () => ({
    user: {
      id: "11111111-1111-4111-8111-111111111111", email: email || "demo@novavpn.test",
      display_name: null, status: "active", locale: "ru", created_at: "2026-11-24T09:00:00Z",
    },
    plan: { slug: "internal-default", device_limit: 3, traffic_quota_bytes: null },
    devices: { live: 1, limit: 3 },
  });
  return {
    mode: "stub",
    send(command, args) {
      note(command, "ok");
      switch (command) {
        case "app.info":
          return Promise.resolve({ version: "0.1.0-preview", platform: "windows", web_view: "заглушка", mode: "stub" });
        case "settings.get":
          return Promise.resolve({ api_base_url: apiBaseUrl, window_width: 900, window_height: 700 });
        case "settings.set":
          apiBaseUrl = args.api_base_url;
          return Promise.resolve({ api_base_url: apiBaseUrl, window_width: 900, window_height: 700 });
        case "session.state":
          return Promise.resolve({ signed_in: email !== null, email, api_base_url: apiBaseUrl, startup_error: null });
        case "account.get":
          return email ? Promise.resolve(me()) : fail("unauthenticated", "Сессия не открыта.");
        case "auth.login":
        case "auth.register":
          email = String(args.email);
          return Promise.resolve(me());
        case "auth.logout":
          email = null;
          return Promise.resolve(null);
        case "devices.list":
          return Promise.resolve({ devices: [device], current_device_id: device.id });
        case "devices.create":
          return Promise.resolve(device);
        case "devices.delete":
          return Promise.resolve(null);
        case "servers.list":
          return Promise.resolve(servers);
        case "profiles.list":
          return Promise.resolve(profiles);
        case "profiles.issue": {
          const profile = {
            id: "55555555-5555-4555-8555-555555555555", device_id: device.id, server_id: args.server_id,
            address_v4: "10.66.0.2", status: "active",
            issued_at: "2026-11-24T12:00:00Z", expires_at: "2026-12-24T12:00:00Z",
            overlap_valid_until: null, revoked_at: null,
          };
          profiles = profiles.filter((p) => p.server_id !== args.server_id).concat(profile);
          return Promise.resolve(profile);
        }
        case "profiles.revoke":
          profiles = profiles.map((p) => p.server_id === args.server_id
            ? { ...p, status: "revoked", revoked_at: "2026-11-24T13:00:00Z" }
            : p);
          return Promise.resolve(null);
        case "profiles.export":
          return Promise.resolve({ saved: true, cancelled: false, file_name: "NovaVPN-ams-1.conf", saved_at: "2026-11-24T13:10:00Z" });
        case "diagnostics.get":
          return Promise.resolve({ version: "0.1.0-preview", events: events.slice(0, 20) });
        default:
          return fail("unknown_command", "Неизвестная команда.");
      }
    },
  };
}

let busyCount = 0;

function setBusy(on) {
  busyCount += on ? 1 : -1;
  if (busyCount < 0) busyCount = 0;
  $("busy").hidden = busyCount === 0;
}

async function attempt(command, args) {
  setBusy(true);
  try {
    return { ok: true, data: await bridge.send(command, args) };
  } catch (error) {
    if (error && typeof error === "object") toastError(error);
    return { ok: false, error };
  } finally {
    setBusy(false);
  }
}

function showScreen(name) {
  state.screen = name;
  for (const section of document.querySelectorAll(".screen")) {
    section.hidden = section.id !== "screen-" + name;
  }
  const signedIn = Boolean(state.session && state.session.signed_in);
  $("nav").hidden = !signedIn;
  for (const button of document.querySelectorAll("#nav [data-screen]")) {
    if (button.dataset.screen === name) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  if (name === "home") renderAll();
  if (name === "catalog") renderCatalog();
  if (name === "settings") renderSettings();
  if (name === "diagnostics") void refreshDiagnostics();
  if (name === "auth") renderAuth();
}

function renderAuth() {
  const origin = state.settings ? state.settings.api_base_url : null;
  $("auth-origin").value = origin || "";
  $("auth-credentials").hidden = !origin;
  setText("auth-origin-hint", origin
    ? "Адрес сохранён: " + origin + ". Сменить его можно только до входа."
    : "https:// для любого хоста, http:// — только для 127.0.0.1, localhost или [::1].");
}

function renderAll() {
  renderAccount();
  renderDevices();
  renderProfiles();
  renderCatalog();
}

function renderAccount() {
  const me = state.me;
  if (!me) return;
  setText("account-email", me.user.email);
  setText("account-status", me.user.status === "active" ? "активен" : me.user.status);
  setText("account-plan", me.plan ? me.plan.slug : "активного плана нет");
  setText("account-devices", me.devices.live + " из " + me.devices.limit);
  setText("account-quota", me.plan ? fmtQuota(me.plan.traffic_quota_bytes) : "—");
  const warning = $("account-warning");
  if (me.plan) {
    warning.hidden = true;
    warning.textContent = "";
  } else {
    warning.textContent = "Активного плана нет: выдача профилей недоступна.";
    warning.hidden = false;
  }
}

function renderDevices() {
  const list = $("device-list");
  list.replaceChildren();
  const devices = state.devices ? state.devices.devices : [];
  if (devices.length === 0) {
    list.append(el("li", "row muted", "На аккаунте нет устройств."));
  } else {
    for (const device of devices) {
      const row = el("li", "row");
      const main = el("div", "row-main");
      main.append(el("strong", null, device.name));
      const status = device.revoked_at
        ? "отозвано"
        : device.id === state.currentDeviceId ? "это устройство" : "активно";
      main.append(el("span", device.revoked_at ? "badge badge-danger" : "badge badge-ok", status));
      main.append(el("span", "muted mono", device.id));
      row.append(main);
      row.append(el("span", "muted", "создано " + fmtDate(device.created_at)));
      list.append(row);
    }
  }
  setHiddenFor("forget-device", !state.currentDeviceId);
}

function renderProfiles() {
  const list = $("profile-list");
  list.replaceChildren();
  const select = $("issue-select");
  const issueButton = $("issue-button");
  const hint = $("issue-hint");

  if (!state.currentDeviceId) {
    list.append(el("li", "row muted", "Сначала создайте устройство."));
    select.replaceChildren();
    select.disabled = true;
    issueButton.disabled = true;
    setText("issue-hint", "");
    return;
  }

  if (state.profiles.length === 0) {
    list.append(el("li", "row muted", "Профиль не выдан."));
  }
  for (const profile of state.profiles) {
    const server = state.servers.find((s) => s.id === profile.server_id);
    const row = el("li", "row");
    const main = el("div", "row-main");
    main.append(el("strong", null, server ? server.name : profile.server_id));
    main.append(el("span", profileStatusClass(profile.status), profileStatus(profile.status)));
    main.append(el("span", "mono", profile.address_v4));
    main.append(el("span", "muted",
      "выдан " + fmtDate(profile.issued_at) + " · действует до " + fmtDate(profile.expires_at)));
    row.append(main);
    if (profile.status === "active") {
      const actions = el("div", "row-actions");
      const save = el("button", "btn btn-primary", "Сохранить .conf");
      save.type = "button";
      save.dataset.action = "export";
      save.dataset.server = profile.server_id;
      const revoke = el("button", "btn btn-danger", "Отозвать");
      revoke.type = "button";
      revoke.dataset.action = "revoke";
      revoke.dataset.server = profile.server_id;
      actions.append(save, revoke);
      row.append(actions);
    }
    list.append(row);
  }

  const taken = new Set(state.profiles.filter((p) => p.status !== "revoked").map((p) => p.server_id));
  const options = state.servers.filter((s) => !taken.has(s.id));
  select.replaceChildren();
  for (const server of options) {
    const option = el("option", null,
      server.name + " · " + server.city + " · " + availability(server.availability));
    option.value = server.id;
    select.append(option);
  }
  const hasPlan = Boolean(state.me && state.me.plan);
  const canIssue = options.length > 0 && hasPlan;
  select.disabled = !canIssue;
  issueButton.disabled = !canIssue;
  setText("issue-hint", canIssue
    ? ""
    : hasPlan ? "Нет доступных серверов для выдачи." : "Активного плана нет: выдача профилей недоступна.");
}

function renderCatalog() {
  const list = $("catalog-list");
  list.replaceChildren();
  $("catalog-empty").hidden = state.servers.length !== 0;
  for (const server of state.servers) {
    const card = el("article", "card");
    const head = el("div", "row-main");
    head.append(el("h2", null, server.name));
    head.append(el("span",
      server.availability === "available" ? "badge badge-ok" : "badge badge-muted",
      availability(server.availability)));
    card.append(head);
    card.append(el("p", "muted", server.country_code + " · " + server.city + " · " + server.host + ":" + server.port));
    card.append(el("p", "muted",
      "Задержка: " + latency(server.latency_ms) + " · " + loadText(server.load) + " · " + capacity(server.capacity_mbps)));
    card.append(el("p", "muted", "Провайдер: " + server.provider + " · регион: " + server.region));
    const button = el("button", "btn btn-primary", "Выдать профиль");
    button.type = "button";
    button.dataset.action = "issue";
    button.dataset.server = server.id;
    button.disabled = !state.currentDeviceId || !(state.me && state.me.plan);
    card.append(button);
    list.append(card);
  }
}

function renderSettings() {
  const signedIn = Boolean(state.session && state.session.signed_in);
  $("settings-origin").value = state.settings && state.settings.api_base_url ? state.settings.api_base_url : "";
  $("settings-origin").disabled = signedIn;
  $("settings-save").disabled = signedIn;
  setText("settings-hint", signedIn ? "Чтобы изменить адрес API, выйдите из аккаунта." : "");
  setText("settings-version", state.appInfo
    ? state.appInfo.version + " · " + state.appInfo.platform + " · WebView2 " + state.appInfo.web_view
    : "—");
  setHiddenFor("forget-device", !state.currentDeviceId);
  $("logout").hidden = !signedIn;
}

async function refreshDiagnostics() {
  const result = await attempt("diagnostics.get");
  if (!result.ok) return;
  state.diagnostics = result.data;
  const body = $("diagnostics-body");
  body.replaceChildren();
  $("diagnostics-empty").hidden = result.data.events.length !== 0;
  for (const event of result.data.events) {
    const row = el("tr");
    row.append(el("td", "mono", fmtDate(event.time)));
    row.append(el("td", null, event.command));
    row.append(el("td", null, event.code));
    row.append(el("td", "mono", event.request_id || "—"));
    body.append(row);
  }
  setText("diagnostics-version", result.data.version);
}

async function loadSignedIn() {
  const account = await attempt("account.get");
  if (!account.ok) {
    state.session = null;
    state.me = null;
    state.devices = null;
    state.currentDeviceId = null;
    showScreen("auth");
    return;
  }
  state.me = account.data;
  const devices = await attempt("devices.list");
  if (devices.ok) {
    state.devices = devices.data;
    state.currentDeviceId = devices.data.current_device_id;
  }
  const servers = await attempt("servers.list");
  if (servers.ok) state.servers = servers.data;
  state.profiles = [];
  if (state.currentDeviceId) {
    const profiles = await attempt("profiles.list", { device_id: state.currentDeviceId });
    if (profiles.ok) state.profiles = profiles.data;
  }
  renderAll();
  showScreen("home");
}

async function refreshDeviceData() {
  const devices = await attempt("devices.list");
  if (devices.ok) {
    state.devices = devices.data;
    state.currentDeviceId = devices.data.current_device_id;
  }
  state.profiles = [];
  if (state.currentDeviceId) {
    const profiles = await attempt("profiles.list", { device_id: state.currentDeviceId });
    if (profiles.ok) state.profiles = profiles.data;
  }
  renderAll();
}

async function saveOrigin(inputId) {
  const value = $(inputId).value.trim();
  const result = await attempt("settings.set", { api_base_url: value });
  if (!result.ok) return;
  state.settings = result.data;
  toast("Адрес API сохранён.", "ok");
  renderAuth();
}

async function authenticate(command) {
  const email = $("auth-email").value.trim();
  const password = $("auth-password").value;
  if (email.length === 0) {
    toast("Введите email.", "error");
    return;
  }
  if (password.length < 10) {
    toast("Пароль должен быть не короче 10 символов.", "error");
    return;
  }
  const result = await attempt(command, { email, password });
  $("auth-password").value = "";
  if (!result.ok) return;
  state.me = result.data;
  state.session = {
    signed_in: true,
    email,
    api_base_url: state.settings ? state.settings.api_base_url : null,
    startup_error: null,
  };
  await loadSignedIn();
  toast(command === "auth.register" ? "Аккаунт создан." : "Вы вошли в аккаунт.", "ok");
}

async function logout() {
  const result = await attempt("auth.logout");
  if (!result.ok) return;
  state.me = null;
  state.devices = null;
  state.profiles = [];
  state.servers = [];
  state.currentDeviceId = null;
  state.session = {
    signed_in: false,
    email: null,
    api_base_url: state.settings ? state.settings.api_base_url : null,
    startup_error: null,
  };
  showScreen("auth");
  toast("Вы вышли из аккаунта. Ключ устройства сохранён.", "ok");
}

async function createDevice() {
  const name = ($("device-name").value.trim() || "Windows").slice(0, 64);
  const result = await attempt("devices.create", { name });
  if (!result.ok) return;
  toast("Устройство создано: " + result.data.name, "ok");
  await refreshDeviceData();
}

async function forgetDevice() {
  if (!state.currentDeviceId) return;
  const confirmed = window.confirm(
    "Забыть это устройство? Его профили и сохранённые .conf перестанут работать.");
  if (!confirmed) return;
  const result = await attempt("devices.delete", { device_id: state.currentDeviceId });
  if (!result.ok) return;
  toast("Устройство забыто.", "ok");
  await refreshDeviceData();
}

async function issueProfile(serverId) {
  if (!serverId) return;
  if (!state.currentDeviceId) {
    toast("Сначала создайте устройство.", "error");
    return;
  }
  const result = await attempt("profiles.issue", {
    device_id: state.currentDeviceId,
    server_id: serverId,
  });
  if (!result.ok) return;
  toast("Профиль выдан.", "ok");
  await refreshDeviceData();
}

async function exportProfile(serverId) {
  if (!state.currentDeviceId) return;
  const result = await attempt("profiles.export", {
    device_id: state.currentDeviceId,
    server_id: serverId,
  });
  if (!result.ok) return;
  if (result.data.cancelled) {
    toast("Сохранение отменено.", "info");
    return;
  }
  toast("Файл сохранён: " + result.data.file_name, "ok");
}

async function revokeProfile(serverId) {
  if (!state.currentDeviceId) return;
  const confirmed = window.confirm("Отозвать профиль? Сохранённый .conf перестанет работать.");
  if (!confirmed) return;
  const result = await attempt("profiles.revoke", {
    device_id: state.currentDeviceId,
    server_id: serverId,
  });
  if (!result.ok) return;
  toast("Профиль отозван.", "ok");
  await refreshDeviceData();
}

document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-action]");
  if (!target) return;
  const action = target.dataset.action;
  if (action === "screen") showScreen(target.dataset.screen);
  else if (action === "save-origin") void saveOrigin("auth-origin");
  else if (action === "save-settings") void saveOrigin("settings-origin");
  else if (action === "login") void authenticate("auth.login");
  else if (action === "register") void authenticate("auth.register");
  else if (action === "logout") void logout();
  else if (action === "create-device") void createDevice();
  else if (action === "forget-device") void forgetDevice();
  else if (action === "issue") void issueProfile(target.dataset.server || $("issue-select").value);
  else if (action === "export") void exportProfile(target.dataset.server);
  else if (action === "revoke") void revokeProfile(target.dataset.server);
  else if (action === "refresh-diagnostics") void refreshDiagnostics();
});

async function boot() {
  if (bridge.mode === "stub") $("stub-banner").hidden = false;
  const info = await attempt("app.info");
  if (info.ok) {
    state.appInfo = info.data;
    setText("version-badge", info.data.version);
  }
  const settings = await attempt("settings.get");
  if (settings.ok) state.settings = settings.data;
  const session = await attempt("session.state");
  if (!session.ok) {
    showScreen("auth");
    return;
  }
  state.session = session.data;
  if (session.data.startup_error) {
    $("startup-error").textContent = session.data.startup_error;
    $("startup-error").hidden = false;
  }
  if (!session.data.signed_in) {
    showScreen("auth");
    return;
  }
  await loadSignedIn();
}

void boot().then(() => {
  window.__nova = { booted: true, mode: bridge.mode };
});
