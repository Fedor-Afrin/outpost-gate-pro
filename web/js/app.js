// ---------------------------------------------------------------- утилиты
const $ = (sel) => document.querySelector(sel);

const fmt = (b) => {
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(1)} ${u[i]}`;
};

const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(method, url, body) {
  const r = await fetch(url, {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401 && !url.startsWith("/api/auth/")) {
    showLogin();
    throw new Error("нужен вход");
  }
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`;
    try {
      const j = await r.json();
      msg = Array.isArray(j.detail) ? j.detail.map((d) => d.msg).join("; ") : (j.detail ?? msg);
    } catch (_) { /* не JSON */ }
    throw new Error(msg);
  }
  return r.status === 204 ? null : r.json();
}

// ---------------------------------------------------------------- System
async function loadSystem() {
  const s = await api("GET", "/api/system/resource");
  $("#sysinfo").innerHTML =
    `${esc(s.hostname)}<br>kernel ${esc(s.kernel)}<br>mode: ${esc(s.mode)}<br>ip_forward: ${s.ip_forward ? "on" : "off"}`;
}

// ---------------------------------------------------------------- Status
let lastTraffic = null;   // прошлый замер — для скорости
const rate = (bytes, sec) => sec > 0 ? `${fmt(bytes / sec)}/с` : "—";

function scard(title, ok, lines, link) {
  const dot = ok === true ? "ok" : ok === false ? "bad" : "off";
  return `<h2><span class="dot ${dot}"></span>${title}<a class="more" href="#${link}">настроить →</a></h2>`
    + lines.filter(Boolean).map(([k, v]) => `<div class="kv"><span>${k}</span><b>${v}</b></div>`).join("");
}

async function loadStatus() {
  const s = await api("GET", "/api/status");
  const w = s.wan, v = s.vpn, l = s.lan, y = s.system;

  $("#st-wan").innerHTML = w.error ? scard("WAN", false, [["Ошибка", esc(w.error)]], "wan")
    : scard("WAN", w.link_up && w.addresses.length > 0 && !!w.gateway, [
        ["Интерфейс", `${esc(w.interface ?? "—")} · ${w.link_up ? "кабель есть" : "нет кабеля"}`],
        ["Режим", { dhcp: "DHCP", static: "вручную", none: "не настраивается" }[w.mode] ?? w.mode],
        ["Адрес", w.addresses.map(esc).join(", ") || "—"],
        ["Шлюз", esc(w.gateway ?? "—")],
        ["DNS", esc(w.dns.join(", ") || "—")],
      ], "wan");

  const vpnName = { wireguard: "WireGuard", amneziawg: "AmneziaWG", l2tp: "L2TP/IPsec" };
  $("#st-vpn").innerHTML = v.error ? scard("VPN", false, [["Ошибка", esc(v.error)]], "vpn")
    : !v.enabled ? scard("VPN", null, [["Туннель", "выключен"]], "vpn")
    : scard(`VPN · ${vpnName[v.enabled]}`, v.connected, [
        ["Состояние", v.connected ? "подключён" : "нет связи с сервером"],
        ["Сервер", esc(v.endpoint ?? "—")],
        ["Адрес в туннеле", esc(v.tunnel_ip ?? "—")],
        ["Режим", (v.mode === "full" ? "весь трафик" : "только сети компании") + (v.killswitch ? " · kill switch" : "")],
        v.latest_handshake ? ["Handshake", ago(v.latest_handshake)] : null,
        v.enabled === "l2tp" ? ["IPsec", v.ipsec_up ? "установлен" : "нет"] : null,
        ["Трафик", `↓ ${fmt(v.rx_bytes)} ↑ ${fmt(v.tx_bytes)}`],
      ], "vpn");

  $("#st-lan").innerHTML = l.error ? scard("LAN", false, [["Ошибка", esc(l.error)]], "lan")
    : !l.enabled ? scard("LAN", null, [["LAN", "выключен"]], "lan")
    : scard("LAN", l.active && l.dns_dhcp_running, [
        ["Адрес роутера", esc(l.address)],
        ["Порты", `${l.ports_up} из ${l.ports} с кабелем`],
        ["Устройства", `${l.clients} по DHCP` + (l.static ? ` · закреплено ${l.static}` : "")],
        ["DHCP и DNS", l.dns_dhcp_running ? "работают" : "не запущены"],
        s.firewall.error ? null : ["Фаервол", s.firewall.active
          ? `активен · правил ${s.firewall.rules} · пробросов ${s.firewall.forwards}` : "не активен"],
      ], "lan");

  $("#st-sys").innerHTML = y.error ? scard("Система", false, [["Ошибка", esc(y.error)]], "system")
    : scard(esc(y.identity), true, [
        ["Uptime", duration(y.uptime)],
        ["CPU / память", `${y.cpu_percent ?? "…"}% / ${y.memory_percent ?? "—"}%`],
        ["Диск", `${y.disk_percent}%`],
        y.temperature != null ? ["Температура", `${y.temperature} °C`] : null,
        ["Версия", `${esc(y.version)} · ${esc(y.mode)}`],
        y.safe_mode ? ["Safe Mode", "включён"] : null,
      ], "system");

  if (!s.traffic.error) {
    const prev = lastTraffic;
    const dt = prev ? s.time - prev.time : 0;
    const before = Object.fromEntries((prev?.traffic ?? []).map((i) => [i.name, i]));
    $("#st-traffic").innerHTML = s.traffic.map((i) => {
      const p = before[i.name];
      return `<tr><td>${esc(i.name)}</td><td>${i.role ? `<span class="badge ${i.role === "wan" ? "wan" : "lan"}">${i.role.toUpperCase()}</span>` : ""}</td>
        <td>${i.running ? '<span class="flag-r">есть</span>' : '<span class="flag-x">нет</span>'}</td>
        <td>${p ? rate(i.rx_bytes - p.rx_bytes, dt) : "…"}</td><td>${p ? rate(i.tx_bytes - p.tx_bytes, dt) : "…"}</td>
        <td>${fmt(i.rx_bytes)}</td><td>${fmt(i.tx_bytes)}</td></tr>`;
    }).join("");
    lastTraffic = s;
  }
}

// ---------------------------------------------------------------- WAN
const STATE_TEXT = {
  bound: "адрес получен по DHCP",
  searching: "ищу DHCP-сервер…",
  static: "настроен вручную",
  none: "не управляется роутером",
};
let wanFormLoaded = false;

function wanModeChanged() {
  const mode = $("#wan-form").querySelector("input[name=mode]:checked")?.value;
  $("#wan-static").hidden = mode !== "static";
}

function fillWanForm(w) {
  const f = $("#wan-form");
  const c = w.config;
  const opts = ["auto", ...w.interfaces];
  if (c.interface !== "auto" && !opts.includes(c.interface)) opts.push(c.interface);
  $("#wan-iface").innerHTML = opts.map((n) =>
    `<option value="${esc(n)}" ${n === c.interface ? "selected" : ""}>${n === "auto" ? "auto (по маршруту по умолчанию)" : esc(n)}</option>`).join("");
  f.querySelector(`input[name=mode][value=${c.mode}]`).checked = true;
  f.address.value = c.address ?? "";
  f.gateway.value = c.gateway ?? "";
  f.dns1.value = c.dns[0] ?? "";
  f.dns2.value = c.dns[1] ?? "";
  wanModeChanged();
}

async function loadWan() {
  const w = await api("GET", "/api/wan");
  $("#ws-iface").textContent = w.interface ?? "не найден";
  $("#ws-link").innerHTML = w.link_up ? '<span class="flag-r">есть</span>' : '<span class="flag-x">нет кабеля</span>';
  $("#ws-state").textContent = STATE_TEXT[w.dhcp_state] ?? (w.dhcp_state || "—");
  $("#ws-addr").innerHTML = w.addresses.length ? w.addresses.map(esc).join("<br>") : "—";
  $("#ws-gw").textContent = w.gateway ?? "—";
  $("#ws-dns").textContent = w.dns.length ? w.dns.join(", ") : "—";
  $("#ws-mac").textContent = w.mac ?? "—";
  $("#ws-lease").textContent = w.lease_expires ? new Date(w.lease_expires * 1000).toLocaleString(I18N.locale()) : "—";
  $("#wan-renew").hidden = !w.dhcp_running;
  if (!wanFormLoaded) { fillWanForm(w); wanFormLoaded = true; }
}

$("#wan-form").addEventListener("change", (ev) => { if (ev.target.name === "mode") wanModeChanged(); });

$("#wan-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const mode = f.get("mode");
  $("#wan-error").textContent = "";
  $("#wan-ok").textContent = "";
  try {
    const w = await api("PUT", "/api/wan", {
      interface: f.get("interface"),
      mode,
      address: mode === "static" ? f.get("address") || null : null,
      gateway: mode === "static" ? f.get("gateway") || null : null,
      dns: [f.get("dns1"), f.get("dns2")].filter(Boolean),
    });
    fillWanForm(w);
    $("#wan-ok").textContent = "Применено";
    await loadWan();
  } catch (e) {
    $("#wan-error").textContent = e.message;
  }
});

$("#wan-renew").addEventListener("click", async () => {
  try { await api("POST", "/api/wan/renew"); await loadWan(); }
  catch (e) { $("#wan-error").textContent = e.message; }
});

// ---------------------------------------------------------------- LAN
const ROLE = { wan: '<span class="badge wan">WAN</span>', lan: '<span class="badge lan">LAN</span>', none: "—" };
let lanFormLoaded = false;

function lanPortsAutoChanged() {
  const auto = $("#lan-form").ports_auto.checked;
  $("#lan-port-list").querySelectorAll("input").forEach((i) => { i.disabled = auto; });
}

function fillLanForm(l) {
  const f = $("#lan-form");
  const c = l.config;
  f.enabled.checked = c.enabled;
  f.address.value = c.address;
  f.ports_auto.checked = c.ports.length === 0;
  const candidates = l.ports.filter((p) => p.role !== "wan");
  $("#lan-port-list").innerHTML = candidates.map((p) => `
    <label class="check"><input type="checkbox" name="port" value="${esc(p.name)}"
      ${c.ports.length === 0 || c.ports.includes(p.name) ? "checked" : ""}> ${esc(p.name)}</label>`).join("")
    || '<span class="hint">нет свободных портов</span>';
  f.dhcp_enabled.checked = c.dhcp_enabled;
  f.pool_start.value = c.pool_start ?? "";
  f.pool_end.value = c.pool_end ?? "";
  f.lease_time.value = c.lease_time;
  if (!f.lease_time.value) f.lease_time.add(new Option(c.lease_time, c.lease_time, true, true));
  f.wan_management.checked = c.wan_management;
  lanPortsAutoChanged();
}

async function loadLan() {
  const l = await api("GET", "/api/lan");
  $("#ls-state").innerHTML = l.active ? '<span class="flag-r">работает</span>'
    : (l.config.enabled ? '<span class="flag-x">ошибка — см. docker logs</span>' : "выключен");
  $("#ls-dns").textContent = l.dns_dhcp_running ? "dnsmasq работает" : "не запущен";
  $("#ls-bridge").textContent = l.active ? l.bridge : "—";
  $("#ls-addr").textContent = l.active ? l.config.address : "—";
  $("#lan-ports").innerHTML = l.ports.map((p) => `
    <tr><td>${esc(p.name)}</td><td>${ROLE[p.role]}</td>
        <td>${p.link_up ? '<span class="flag-r">есть</span>' : '<span class="flag-x">нет</span>'}</td>
        <td>${esc(p.mac)}</td></tr>`).join("");
  $("#lan-leases").innerHTML = l.leases.map((d) => `
    <tr><td>${esc(d.name ?? d.hostname ?? "—")}</td><td>${esc(d.ip)}</td><td>${esc(d.mac)}</td>
        <td>${esc(d.vendor ?? "—")}</td>
        <td>${d.expires ? new Date(d.expires * 1000).toLocaleString(I18N.locale()) : "бессрочно"}</td>
        <td class="actions">${d.static ? '<span class="badge lan">закреплён</span>'
          : `<button type="button" data-pin="${esc(d.mac)}" data-ip="${esc(d.ip)}" data-name="${esc(d.hostname ?? "")}">Закрепить</button>`}</td></tr>`).join("")
    || '<tr><td colspan="6" class="hint">пока никого</td></tr>';
  renderStatic(l.static_leases);
  if (!lanFormLoaded) { fillLanForm(l); lanFormLoaded = true; }
}

$("#lan-form").addEventListener("change", (ev) => { if (ev.target.name === "ports_auto") lanPortsAutoChanged(); });

$("#lan-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("#lan-error").textContent = "";
  $("#lan-ok").textContent = "";
  const ports = f.ports_auto.checked ? []
    : [...f.querySelectorAll("input[name=port]:checked")].map((i) => i.value);
  try {
    const l = await api("PUT", "/api/lan", {
      enabled: f.enabled.checked,
      address: f.address.value,
      ports,
      dhcp_enabled: f.dhcp_enabled.checked,
      pool_start: f.pool_start.value || null,
      pool_end: f.pool_end.value || null,
      lease_time: f.lease_time.value,
      wan_management: f.wan_management.checked,
    });
    fillLanForm(l);
    $("#lan-ok").textContent = "Применено";
    await loadLan();
  } catch (e) {
    $("#lan-error").textContent = e.message;
  }
});

// ---------------------------------------------------------------- LAN: закреплённые адреса
function renderStatic(list) {
  $("#static-leases").innerHTML = list.map((x) => `
    <tr class="${x.valid ? "" : "row-inactive"}"><td>${esc(x.name ?? "—")}</td><td>${esc(x.ip)}</td><td>${esc(x.mac)}</td>
      <td>${!x.valid ? "вне сети LAN — не работает" : x.in_pool ? "внутри пула DHCP" : ""}</td>
      <td class="actions"><button type="button" data-unpin="${esc(x.mac)}" class="danger">Открепить</button></td></tr>`).join("")
    || '<tr><td colspan="5" class="hint">нет</td></tr>';
}

$("#lan-leases").addEventListener("click", (ev) => {
  const b = ev.target.closest("button[data-pin]");
  if (!b) return;
  const f = $("#static-form");
  f.mac.value = b.dataset.pin;
  f.ip.value = b.dataset.ip;
  f.name.value = b.dataset.name;
  $("#static-card").scrollIntoView({ behavior: "smooth" });
  f.ip.focus();
});

$("#static-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("#static-error").textContent = "";
  try {
    renderStatic(await api("POST", "/api/lan/static-leases",
      { mac: f.mac.value, ip: f.ip.value, name: f.name.value || null }));
    f.reset();
    await loadLan();
  } catch (e) { $("#static-error").textContent = e.message; }
});

$("#static-leases").addEventListener("click", async (ev) => {
  const b = ev.target.closest("button[data-unpin]");
  if (!b) return;
  $("#static-error").textContent = "";
  try {
    renderStatic(await api("DELETE", `/api/lan/static-leases/${encodeURIComponent(b.dataset.unpin)}`));
    await loadLan();
  } catch (e) { $("#static-error").textContent = e.message; }
});

// ---------------------------------------------------------------- VPN: вкладки
let vpnKind = "wireguard";
let wgFormLoaded = false;
let l2tpFormLoaded = false;
const VPN_NAMES = { wireguard: "WireGuard", amneziawg: "AmneziaWG", l2tp: "L2TP/IPsec" };
const splitList = (v) => v.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);

function selectVpnTab(kind) {
  vpnKind = kind;
  wgFormLoaded = false;
  l2tpFormLoaded = false;
  document.querySelectorAll("#vpn-tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.kind === kind));
  $("#wg-panel").hidden = kind === "l2tp";
  $("#l2tp-panel").hidden = kind !== "l2tp";
  $("#awg-obf").hidden = kind !== "amneziawg";
  ["#wg-error", "#wg-ok", "#wg-parse-msg", "#l2tp-error", "#l2tp-ok"].forEach((id) => { $(id).textContent = ""; });
  loadVpn().catch(console.error);
}

$("#vpn-tabs").addEventListener("click", (ev) => {
  const t = ev.target.closest(".tab");
  if (t) selectVpnTab(t.dataset.kind);
});

async function loadVpn() {
  const sum = await api("GET", "/api/vpn");
  document.querySelectorAll("#vpn-tabs .tab").forEach((t) => {
    t.textContent = VPN_NAMES[t.dataset.kind] + (sum.enabled === t.dataset.kind ? " ●" : "");
  });
  $("#vpn-active-hint").textContent = sum.enabled
    ? `Сейчас включён: ${VPN_NAMES[sum.enabled]}. Одновременно работает один туннель — включение другого выключит этот.`
    : "Туннель не включён. Одновременно работает один туннель.";
  return vpnKind === "l2tp" ? loadL2tp() : loadWg();
}

function ago(ts) {
  const s = Math.round(Date.now() / 1000 - ts);
  return s < 60 ? `${s} с назад` : s < 3600 ? `${Math.round(s / 60)} мин назад` : new Date(ts * 1000).toLocaleString(I18N.locale());
}

// ---------------------------------------------------------------- VPN → WireGuard / AmneziaWG
function wgModeChanged() {
  const f = $("#wg-form");
  f.killswitch.disabled = f.querySelector("input[name=mode]:checked")?.value !== "full";
}

function fillWgForm(c, privateKeySet) {
  const f = $("#wg-form");
  f.enabled.checked = c.enabled;
  f.querySelector(`input[name=mode][value=${c.mode}]`).checked = true;
  f.killswitch.checked = c.killswitch;
  f.nat.checked = c.nat;
  f.private_key.value = c.private_key ?? "";
  f.private_key.placeholder = privateKeySet ? "задан — пусто = не менять" : "";
  f.addresses.value = c.addresses.join(", ");
  f.dns.value = c.dns.join(", ");
  f.mtu.value = c.mtu;
  f.peer_public_key.value = c.peer_public_key ?? "";
  f.preshared_key.value = c.preshared_key ?? "";
  f.endpoint.value = c.endpoint ?? "";
  f.allowed_ips.value = c.allowed_ips.join(", ");
  f.keepalive.value = c.keepalive;
  f.obfuscation.value = Object.entries(c.obfuscation ?? {}).map(([k, v]) => `${k} = ${v}`).join("\n");
  wgModeChanged();
}

function parseObfuscation(text) {
  const out = {};
  text.split("\n").map((l) => l.trim()).filter(Boolean).forEach((l) => {
    const i = l.indexOf("=");
    if (i > 0) out[l.slice(0, i).trim()] = l.slice(i + 1).trim();
  });
  return out;
}

async function loadWg() {
  const w = await api("GET", `/api/vpn/${vpnKind}`);
  $("#vs-state").innerHTML = !w.config.enabled ? "выключен"
    : w.connected ? '<span class="flag-r">подключён</span>'
    : w.active ? '<span class="flag-x">нет связи с сервером</span>' : '<span class="flag-x">ошибка — см. docker logs</span>';
  $("#vs-hs").textContent = w.latest_handshake ? ago(w.latest_handshake) : "—";
  $("#vs-endpoint").textContent = w.config.endpoint ? `${w.config.endpoint}${w.endpoint_ip ? " (" + w.endpoint_ip + ")" : ""}` : "—";
  $("#vs-traffic").textContent = w.active ? `↓ ${fmt(w.rx_bytes)}  ↑ ${fmt(w.tx_bytes)}` : "—";
  $("#vs-pub").textContent = w.public_key ?? "—";
  $("#vs-error").textContent = w.error ?? "";
  if (!wgFormLoaded) { fillWgForm(w.config, w.private_key_set); wgFormLoaded = true; }
}

$("#wg-form").addEventListener("change", (ev) => { if (ev.target.name === "mode") wgModeChanged(); });

$("#wg-file").addEventListener("change", async (ev) => {
  const file = ev.target.files[0];
  if (file) $("#wg-import").value = await file.text();
});

$("#wg-parse").addEventListener("click", async () => {
  $("#wg-parse-msg").textContent = "";
  $("#wg-error").textContent = "";
  try {
    const c = await api("POST", `/api/vpn/${vpnKind}/parse`, { text: $("#wg-import").value });
    c.enabled = true;
    fillWgForm(c, false);
    $("#wg-parse-msg").textContent = "Поля заполнены — проверьте и нажмите «Применить»";
  } catch (e) { $("#wg-error").textContent = e.message; }
});

$("#wg-genkey").addEventListener("click", async () => {
  try {
    const k = await api("POST", "/api/vpn/genkey");
    $("#wg-form").private_key.value = k.private_key;
    $("#wg-ok").textContent = `Публичный ключ роутера: ${k.public_key}`;
  } catch (e) { $("#wg-error").textContent = e.message; }
});

$("#wg-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("#wg-error").textContent = "";
  $("#wg-ok").textContent = "";
  try {
    const w = await api("PUT", `/api/vpn/${vpnKind}`, {
      enabled: f.enabled.checked,
      mode: f.querySelector("input[name=mode]:checked").value,
      killswitch: f.killswitch.checked,
      nat: f.nat.checked,
      private_key: f.private_key.value || null,
      addresses: splitList(f.addresses.value),
      dns: splitList(f.dns.value),
      mtu: Number(f.mtu.value || 1420),
      peer_public_key: f.peer_public_key.value || null,
      preshared_key: f.preshared_key.value || null,
      endpoint: f.endpoint.value || null,
      allowed_ips: splitList(f.allowed_ips.value),
      keepalive: Number(f.keepalive.value || 0),
      obfuscation: vpnKind === "amneziawg" ? parseObfuscation(f.obfuscation.value) : {},
    });
    fillWgForm(w.config, w.private_key_set);
    $("#wg-ok").textContent = "Применено";
    await loadVpn();
  } catch (e) { $("#wg-error").textContent = e.message; }
});

// ---------------------------------------------------------------- VPN → L2TP/IPsec
function l2tpModeChanged() {
  const f = $("#l2tp-form");
  f.killswitch.disabled = f.querySelector("input[name=mode]:checked")?.value !== "full";
}

function fillL2tpForm(st) {
  const f = $("#l2tp-form");
  const c = st.config;
  f.enabled.checked = c.enabled;
  f.querySelector(`input[name=mode][value=${c.mode}]`).checked = true;
  f.killswitch.checked = c.killswitch;
  f.nat.checked = c.nat;
  f.server.value = c.server ?? "";
  f.psk.value = "";
  f.psk.placeholder = st.psk_set ? "задан — пусто = не менять" : "";
  f.username.value = c.username ?? "";
  f.password.value = "";
  f.password.placeholder = st.password_set ? "задан — пусто = не менять" : "";
  f.networks.value = c.networks.join(", ");
  f.mtu.value = c.mtu;
  l2tpModeChanged();
}

async function loadL2tp() {
  const st = await api("GET", "/api/vpn/l2tp");
  $("#ls2-state").innerHTML = !st.config.enabled ? "выключен"
    : st.connected ? '<span class="flag-r">подключён</span>' : '<span class="flag-x">подключаюсь…</span>';
  $("#ls2-ipsec").innerHTML = !st.config.enabled ? "—"
    : st.ipsec_up ? '<span class="flag-r">установлен</span>' : '<span class="flag-x">нет</span>';
  $("#ls2-server").textContent = st.config.server ? `${st.config.server}${st.endpoint_ip ? " (" + st.endpoint_ip + ")" : ""}` : "—";
  $("#ls2-ip").textContent = st.local_ip ? `${st.local_ip} ↔ ${st.remote_ip}` : "—";
  $("#ls2-traffic").textContent = st.connected ? `↓ ${fmt(st.rx_bytes)}  ↑ ${fmt(st.tx_bytes)}` : "—";
  $("#ls2-error").textContent = st.error ?? "";
  if (!l2tpFormLoaded) { fillL2tpForm(st); l2tpFormLoaded = true; }
}

$("#l2tp-form").addEventListener("change", (ev) => { if (ev.target.name === "mode") l2tpModeChanged(); });

$("#l2tp-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("#l2tp-error").textContent = "";
  $("#l2tp-ok").textContent = "";
  try {
    const st = await api("PUT", "/api/vpn/l2tp", {
      enabled: f.enabled.checked,
      mode: f.querySelector("input[name=mode]:checked").value,
      killswitch: f.killswitch.checked,
      nat: f.nat.checked,
      server: f.server.value || null,
      psk: f.psk.value || null,
      username: f.username.value || null,
      password: f.password.value || null,
      networks: splitList(f.networks.value),
      mtu: Number(f.mtu.value || 1400),
    });
    fillL2tpForm(st);
    $("#l2tp-ok").textContent = "Применено";
    await loadVpn();
  } catch (e) { $("#l2tp-error").textContent = e.message; }
});

// ---------------------------------------------------------------- Firewall
let fwTab = "input";
let fwEditId = null;     // id правила, которое редактируем (null — новое)
let pfEditId = null;
let fwData = null;
const ZONE = { any: "Любой", wan: "WAN", lan: "LAN", vpn: "VPN" };
const ACTION = { accept: '<span class="act accept">Разрешить</span>', drop: '<span class="act drop">Запретить</span>',
                 reject: '<span class="act drop">Отклонить</span>' };
const PROTO = { all: "Все", tcp: "TCP", udp: "UDP", icmp: "ICMP", "tcp+udp": "TCP и UDP" };
const HINTS = {
  input: "Кто может подключаться к самому роутеру. Правила проверяются сверху вниз, первое совпавшее решает; затем — системные правила.",
  forward: "Трафик через роутер между LAN, WAN и VPN. Например: запретить устройству интернет или открыть центру по VPN только нужный порт.",
};

function selectFwTab(tab) {
  fwTab = tab;
  document.querySelectorAll("#fw-tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === tab));
  $("#fw-rules-panel").hidden = !(tab === "input" || tab === "forward");
  $("#fw-forwards-panel").hidden = tab !== "forwards";
  $("#fw-ruleset-panel").hidden = tab !== "ruleset";
  document.querySelectorAll(".fwd-col").forEach((c) => { c.hidden = tab !== "forward"; });
  closeFwForm();
  loadFirewall().catch(console.error);
}

$("#fw-tabs").addEventListener("click", (ev) => {
  const t = ev.target.closest(".tab");
  if (t) selectFwTab(t.dataset.tab);
});

const counter = (x) => x.packets ? `${x.packets} пак. / ${fmt(x.bytes)}` : "—";
const cidr = (v) => v ?? '<span class="hint">0.0.0.0/0</span>';

async function loadFirewall() {
  if (fwTab === "ruleset") {
    $("#fw-ruleset").textContent = (await api("GET", "/api/firewall/ruleset")).text;
    return;
  }
  fwData = await api("GET", "/api/firewall");
  const z = fwData.zones;
  $("#fw-zones").innerHTML = (fwData.active ? '<span class="badge lan">фаервол активен</span>'
      : '<span class="badge wan">не активен — включите LAN</span>')
    + ` WAN: <b>${esc(z.wan ?? "—")}</b> · LAN: <b>${esc(z.lan ?? "—")}</b> · VPN: <b>${esc(z.vpn ?? "—")}</b>`;

  if (fwTab === "forwards") {
    $("#pf-list").innerHTML = fwData.forwards.map((f) => `
      <tr class="${f.enabled ? "" : "row-disabled"}"><td>${f.id}</td><td>${PROTO[f.protocol]}</td><td>${esc(f.wan_port)}</td>
        <td>${esc(f.to_ip)}</td><td>${f.to_port ?? esc(f.wan_port)}</td><td>${cidr(f.src)}</td>
        <td class="desc">${esc(f.description ?? "")}</td><td>${counter(f)}</td>
        <td class="actions"><button type="button" data-pf-edit="${f.id}">Изменить</button>
          <button type="button" data-pf-del="${f.id}" class="danger">Удалить</button></td></tr>`).join("")
      || '<tr><td colspan="9" class="hint">пробросов нет</td></tr>';
    return;
  }

  $("#fw-rules-hint").textContent = HINTS[fwTab];
  const rules = fwData.rules.filter((r) => r.chain === fwTab);
  const fwd = fwTab === "forward";
  $("#fw-rules").innerHTML = rules.map((r, i) => `
    <tr class="${r.enabled ? "" : "row-disabled"}">
      <td>${i + 1}</td><td>${ACTION[r.action]}</td><td>${ZONE[r.in_zone]}</td><td>${cidr(r.src)}</td>
      ${fwd ? `<td>${ZONE[r.out_zone]}</td><td>${cidr(r.dst)}</td>` : ""}
      <td>${PROTO[r.protocol]}</td><td>${esc(r.src_ports ?? "Все")}</td><td>${esc(r.dst_ports ?? "Все")}</td>
      <td class="desc">${esc(r.description ?? "")}</td><td>${counter(r)}</td>
      <td class="actions">
        <button type="button" data-move="up" data-id="${r.id}" ${i === 0 ? "disabled" : ""}>↑</button>
        <button type="button" data-move="down" data-id="${r.id}" ${i === rules.length - 1 ? "disabled" : ""}>↓</button>
        <button type="button" data-edit="${r.id}">Изменить</button>
        <button type="button" data-del="${r.id}" class="danger">Удалить</button></td>
    </tr>`).join("") || `<tr><td colspan="${fwd ? 12 : 10}" class="hint">своих правил нет — работают только системные</td></tr>`;
  $("#fw-system").innerHTML = fwData.system[fwTab].map((x) => `<li>${esc(x)}</li>`).join("")
    + (fwd ? "" : fwData.system.nat.map((x) => `<li>NAT: ${esc(x)}</li>`).join(""));
}

// --- форма правила ---
function openFwForm(rule) {
  const f = $("#fw-form");
  fwEditId = rule ? rule.id : null;
  $("#fw-form-title").textContent = rule ? `Правило #${rules_index(rule)} — изменить` : (fwTab === "input"
    ? "Новое правило: входящие на роутер" : "Новое правило: транзит");
  $("#fw-save").textContent = rule ? "Сохранить" : "Добавить";
  const r = rule ?? { action: "accept", protocol: "tcp", in_zone: fwTab === "input" ? "wan" : "lan",
                      out_zone: "any", enabled: true };
  f.action.value = r.action; f.protocol.value = r.protocol;
  f.in_zone.value = r.in_zone; f.out_zone.value = r.out_zone;
  f.src.value = r.src ?? ""; f.dst.value = r.dst ?? "";
  f.src_ports.value = r.src_ports ?? ""; f.dst_ports.value = r.dst_ports ?? "";
  f.description.value = r.description ?? ""; f.enabled.checked = r.enabled;
  f.querySelectorAll(".fwd-only").forEach((el) => { el.hidden = fwTab !== "forward"; });
  fwProtoChanged();
  f.hidden = false;
  $("#fw-error").textContent = "";
}
const rules_index = (rule) => fwData.rules.filter((r) => r.chain === rule.chain).findIndex((r) => r.id === rule.id) + 1;

function closeFwForm() { $("#fw-form").hidden = true; $("#pf-form").hidden = true; fwEditId = pfEditId = null; }

function fwProtoChanged() {
  const f = $("#fw-form");
  const ports = f.protocol.value === "tcp" || f.protocol.value === "udp";
  f.querySelectorAll(".ports input").forEach((i) => { i.disabled = !ports; if (!ports) i.value = ""; });
}

$("#fw-add").addEventListener("click", () => openFwForm(null));
$("#fw-cancel").addEventListener("click", closeFwForm);
$("#fw-form").addEventListener("change", (ev) => { if (ev.target.name === "protocol") fwProtoChanged(); });

$("#fw-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const body = {
    chain: fwTab, action: f.action.value, protocol: f.protocol.value,
    in_zone: f.in_zone.value, out_zone: fwTab === "forward" ? f.out_zone.value : "any",
    src: f.src.value || null, dst: fwTab === "forward" ? f.dst.value || null : null,
    src_ports: f.src_ports.value || null, dst_ports: f.dst_ports.value || null,
    description: f.description.value || null, enabled: f.enabled.checked,
  };
  try {
    await api(fwEditId ? "PUT" : "POST", fwEditId ? `/api/firewall/rules/${fwEditId}` : "/api/firewall/rules", body);
    closeFwForm();
    await loadFirewall();
  } catch (e) { $("#fw-error").textContent = e.message; }
});

$("#fw-rules").addEventListener("click", async (ev) => {
  const b = ev.target.closest("button");
  if (!b) return;
  $("#fw-error").textContent = "";
  try {
    if (b.dataset.edit) openFwForm(fwData.rules.find((r) => r.id === Number(b.dataset.edit)));
    else if (b.dataset.del) { await api("DELETE", `/api/firewall/rules/${b.dataset.del}`); await loadFirewall(); }
    else if (b.dataset.move) {
      await api("POST", `/api/firewall/rules/${b.dataset.id}/move`, { direction: b.dataset.move });
      await loadFirewall();
    }
  } catch (e) { $("#fw-error").textContent = e.message; }
});

// --- форма проброса ---
function openPfForm(fwd) {
  const f = $("#pf-form");
  pfEditId = fwd ? fwd.id : null;
  $("#pf-form-title").textContent = fwd ? `Проброс #${fwd.id} — изменить` : "Новый проброс";
  $("#pf-save").textContent = fwd ? "Сохранить" : "Добавить";
  const x = fwd ?? { protocol: "tcp", enabled: true };
  f.protocol.value = x.protocol; f.wan_port.value = x.wan_port ?? ""; f.to_ip.value = x.to_ip ?? "";
  f.to_port.value = x.to_port ?? ""; f.src.value = x.src ?? ""; f.description.value = x.description ?? "";
  f.enabled.checked = x.enabled;
  f.hidden = false;
  $("#pf-error").textContent = "";
}

$("#pf-add").addEventListener("click", () => openPfForm(null));
$("#pf-cancel").addEventListener("click", closeFwForm);

$("#pf-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const body = {
    protocol: f.protocol.value, wan_port: f.wan_port.value, to_ip: f.to_ip.value,
    to_port: f.to_port.value ? Number(f.to_port.value) : null, src: f.src.value || null,
    description: f.description.value || null, enabled: f.enabled.checked,
  };
  try {
    await api(pfEditId ? "PUT" : "POST", pfEditId ? `/api/firewall/forwards/${pfEditId}` : "/api/firewall/forwards", body);
    closeFwForm();
    await loadFirewall();
  } catch (e) { $("#pf-error").textContent = e.message; }
});

$("#pf-list").addEventListener("click", async (ev) => {
  const b = ev.target.closest("button");
  if (!b) return;
  $("#pf-error").textContent = "";
  try {
    if (b.dataset.pfEdit) openPfForm(fwData.forwards.find((x) => x.id === Number(b.dataset.pfEdit)));
    else if (b.dataset.pfDel) { await api("DELETE", `/api/firewall/forwards/${b.dataset.pfDel}`); await loadFirewall(); }
  } catch (e) { $("#pf-error").textContent = e.message; }
});

// ---------------------------------------------------------------- Routing (OSPF, BGP)
let rtTab = "overview";
let rtFormLoaded = false;     // форму заполняем один раз, иначе опрос сотрёт то, что вводит человек
let rtData = null;

function selectRtTab(tab) {
  rtTab = tab;
  document.querySelectorAll("#rt-tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === tab));
  $("#rt-overview").hidden = tab !== "overview";
  $("#ospf-form").hidden = tab !== "ospf";
  $("#bgp-form").hidden = tab !== "bgp";
  document.querySelectorAll(".rt-form-error, .rt-form-ok").forEach((x) => { x.textContent = ""; });
  loadRouting().catch(console.error);
}

$("#rt-tabs").addEventListener("click", (ev) => {
  const t = ev.target.closest(".tab");
  if (t) selectRtTab(t.dataset.tab);
});

const rtState = (s) => {
  const ok = /^(Full|Established)/.test(s);
  return `<span class="${ok ? "flag-r" : "flag-x"}">${esc(s || "—")}</span>`;
};
const dash = (v) => (v == null || v === "" ? "—" : esc(v));

async function loadRouting() {
  const d = await api("GET", "/api/routing");
  rtData = d;
  const c = d.config;
  $("#rt-state").innerHTML = !d.installed ? '<span class="flag-x">нет в образе</span>'
    : d.running ? '<span class="flag-r">работает</span>'
    : (c.ospf.enabled || c.bgp.enabled) ? '<span class="flag-x">не запущен</span>' : "выключен";
  $("#rt-rid").textContent = d.router_id || c.router_id || "—";
  const nOspf = d.ospf_neighbors.filter((n) => n.state.startsWith("Full")).length;
  const nBgp = d.bgp_peers.filter((n) => n.state === "Established").length;
  $("#rt-ospf-state").textContent = !c.ospf.enabled ? "выключен" : `соседей ${d.ospf_neighbors.length}, в состоянии Full ${nOspf}`;
  $("#rt-bgp-state").textContent = !c.bgp.enabled ? "выключен" : `AS ${c.bgp.asn} · соседей ${c.bgp.neighbors.length}, установлено ${nBgp}`;
  $("#rt-error").textContent = d.error || "";

  $("#rt-ospf-nb").innerHTML = d.ospf_neighbors.map((n) => `<tr><td>${esc(n.router_id)}</td><td>${dash(n.address)}</td>
    <td>${dash(n.interface)}</td><td>${rtState(n.state)}</td><td>${dash(n.priority)}</td><td>${dash(n.uptime)}</td></tr>`).join("")
    || `<tr><td colspan="6" class="hint">${c.ospf.enabled ? "соседей пока нет" : "OSPF выключен"}</td></tr>`;
  $("#rt-bgp-nb").innerHTML = d.bgp_peers.map((n) => `<tr class="${n.enabled ? "" : "row-disabled"}"><td>${esc(n.address)}</td>
    <td>${dash(n.remote_as)}</td><td>${dash(n.description)}</td><td>${rtState(n.state)}</td><td>${dash(n.uptime)}</td>
    <td>${dash(n.prefixes_received)}</td><td>${dash(n.prefixes_sent)}</td></tr>`).join("")
    || `<tr><td colspan="7" class="hint">${c.bgp.enabled ? "соседей нет" : "BGP выключен"}</td></tr>`;
  $("#rt-routes").innerHTML = d.routes.map((r) => `<tr><td>${esc(r.prefix)}</td>
    <td><span class="badge ${r.protocol === "ospf" ? "lan" : "wan"}">${r.protocol.toUpperCase()}</span></td>
    <td>${dash(r.nexthop)}</td><td>${dash(r.interface)}</td><td>${dash(r.distance)}</td><td>${dash(r.metric)}</td>
    <td>${r.selected ? '<span class="flag-r">да</span>' : "—"}</td></tr>`).join("")
    || '<tr><td colspan="7" class="hint">маршрутов от OSPF и BGP нет</td></tr>';

  $("#rt-ifnames").innerHTML = d.interfaces.map((n) => `<option value="${esc(n)}">`).join("");
  if (!rtFormLoaded) { fillRoutingForms(c); rtFormLoaded = true; }
}

// --- строки редактируемых таблиц ---
const inp = (name, value, attrs = "") => `<input name="${name}" value="${esc(value ?? "")}" ${attrs}>`;
const OSPF_TYPES = ["auto", "point-to-point", "broadcast", "non-broadcast"];
const SECRET = "********";    // так сервер показывает заданный пароль; оставить = не менять

function ospfNetRow(n = {}) {
  return `<tr data-row="ospf-net"><td>${inp("network", n.network, 'placeholder="192.168.88.0/24" size="18"')}</td>
    <td>${inp("area", n.area ?? "0.0.0.0", 'size="10"')}</td>
    <td><button type="button" class="danger" data-del-row>×</button></td></tr>`;
}

function ospfIfaceRow(i = {}) {
  const types = OSPF_TYPES.map((t) => `<option value="${t}" ${t === (i.network_type || "auto") ? "selected" : ""}>${t}</option>`).join("");
  return `<tr data-row="ospf-iface"><td>${inp("name", i.name, 'list="rt-ifnames" placeholder="wg0" size="8"')}</td>
    <td>${inp("cost", i.cost, 'type="number" min="1" max="65535" class="narrow"')}</td>
    <td><select name="network_type">${types}</select></td>
    <td><input type="checkbox" name="passive" ${i.passive ? "checked" : ""}></td>
    <td>${inp("hello", i.hello ?? 10, 'type="number" min="1" class="narrow"')}</td>
    <td>${inp("dead", i.dead ?? 40, 'type="number" min="2" class="narrow"')}</td>
    <td>${inp("auth_key", i.auth_key, 'type="password" size="10" autocomplete="off"')}</td>
    <td>${inp("neighbor", i.neighbor, 'placeholder="10.8.0.1" size="11"')}</td>
    <td><button type="button" class="danger" data-del-row>×</button></td></tr>`;
}

function bgpNbBlock(n = {}) {
  return `<div class="nb-block" data-row="bgp-nb">
    <div class="nb-grid">
      <label>Адрес соседа ${inp("address", n.address, 'placeholder="10.8.0.1"')}</label>
      <label>AS соседа ${inp("remote_as", n.remote_as, 'type="number" min="1" placeholder="65000"')}</label>
      <label>Описание ${inp("description", n.description, 'placeholder="Центральный офис"')}</label>
      <label>Пароль MD5 ${inp("password", n.password, 'type="password" autocomplete="off"')}</label>
      <label>eBGP multihop ${inp("multihop", n.multihop, 'type="number" min="2" max="255" placeholder="—"')}</label>
      <label>Источник (update-source) ${inp("update_source", n.update_source, 'placeholder="lo или 10.255.0.1"')}</label>
      <label>Keepalive, с ${inp("keepalive", n.keepalive ?? 60, 'type="number" min="1"')}</label>
      <label>Hold, с ${inp("hold", n.hold ?? 180, 'type="number" min="3"')}</label>
      <label class="wide">Принимать только ${inp("prefix_in", (n.prefix_in || []).join(", "), 'placeholder="10.0.0.0/8 le 24"')}</label>
      <label class="wide">Отдавать только ${inp("prefix_out", (n.prefix_out || []).join(", "), 'placeholder="192.168.88.0/24"')}</label>
    </div>
    <div class="toolbar">
      <label class="check"><input type="checkbox" name="nb_enabled" ${n.enabled === false ? "" : "checked"}> Сосед включён</label>
      <button type="button" class="danger" data-del-row>Удалить соседа</button>
    </div>
  </div>`;
}

const ROW_NEW = { "ospf-net": ["#ospf-nets", ospfNetRow], "ospf-iface": ["#ospf-ifaces", ospfIfaceRow],
                  "bgp-nb": ["#bgp-neighbors", bgpNbBlock] };

document.querySelectorAll(".rt-form").forEach((form) => form.addEventListener("click", (ev) => {
  const add = ev.target.closest("[data-add]");
  if (add) {
    const [box, make] = ROW_NEW[add.dataset.add];
    $(box).insertAdjacentHTML("beforeend", make());
    return;
  }
  const del = ev.target.closest("[data-del-row]");
  if (del) del.closest("[data-row]").remove();
}));

function setChecks(form, name, values) {
  form.querySelectorAll(`input[name=${name}]`).forEach((x) => { x.checked = values.includes(x.value); });
}
const getChecks = (form, name) => [...form.querySelectorAll(`input[name=${name}]:checked`)].map((x) => x.value);
const list = (s) => s.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
const prefixes = (s) => s.split(",").map((x) => x.trim()).filter(Boolean);
const num = (v) => (v === "" || v == null ? null : Number(v));
const opt = (v) => (v.trim() === "" ? null : v.trim());

function fillRoutingForms(c) {
  const o = $("#ospf-form"), b = $("#bgp-form");
  o.enabled.checked = c.ospf.enabled;
  o.router_id.value = b.router_id.value = c.router_id ?? "";
  $("#ospf-nets").innerHTML = c.ospf.networks.map(ospfNetRow).join("");
  $("#ospf-ifaces").innerHTML = c.ospf.interfaces.map(ospfIfaceRow).join("");
  o.passive_default.checked = c.ospf.passive_default;
  setChecks(o, "redistribute", c.ospf.redistribute);
  o.default_route.value = c.ospf.default_route;

  b.enabled.checked = c.bgp.enabled;
  b.asn.value = c.bgp.asn;
  b.networks.value = c.bgp.networks.join(", ");
  setChecks(b, "redistribute", c.bgp.redistribute);
  $("#bgp-neighbors").innerHTML = c.bgp.neighbors.map(bgpNbBlock).join("");
}

function collectRouting(routerId) {
  const o = $("#ospf-form"), b = $("#bgp-form");
  const val = (row, name) => row.querySelector(`[name=${name}]`).value;
  return {
    router_id: opt(routerId),
    ospf: {
      enabled: o.enabled.checked,
      networks: [...$("#ospf-nets").querySelectorAll("[data-row]")].map((r) => ({ network: val(r, "network").trim(), area: val(r, "area").trim() || "0" }))
        .filter((n) => n.network),
      interfaces: [...$("#ospf-ifaces").querySelectorAll("[data-row]")].map((r) => ({
        name: val(r, "name").trim(), cost: num(val(r, "cost")), network_type: val(r, "network_type"),
        passive: r.querySelector("[name=passive]").checked, hello: num(val(r, "hello")) ?? 10, dead: num(val(r, "dead")) ?? 40,
        auth_key: opt(val(r, "auth_key")), neighbor: opt(val(r, "neighbor")),
      })).filter((i) => i.name),
      passive_default: o.passive_default.checked,
      redistribute: getChecks(o, "redistribute"),
      default_route: o.default_route.value,
    },
    bgp: {
      enabled: b.enabled.checked,
      asn: num(b.asn.value) ?? 65001,
      networks: list(b.networks.value),
      redistribute: getChecks(b, "redistribute"),
      neighbors: [...$("#bgp-neighbors").querySelectorAll("[data-row]")].map((r) => ({
        address: val(r, "address").trim(), remote_as: num(val(r, "remote_as")),
        description: opt(val(r, "description")), password: opt(val(r, "password")),
        multihop: num(val(r, "multihop")), update_source: opt(val(r, "update_source")),
        keepalive: num(val(r, "keepalive")) ?? 60, hold: num(val(r, "hold")) ?? 180,
        prefix_in: prefixes(val(r, "prefix_in")), prefix_out: prefixes(val(r, "prefix_out")),
        enabled: r.querySelector("[name=nb_enabled]").checked,
      })).filter((n) => n.address),
    },
  };
}

document.querySelectorAll(".rt-form").forEach((form) => form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = form.querySelector(".rt-form-error"), ok = form.querySelector(".rt-form-ok");
  err.textContent = ""; ok.textContent = "";
  const btn = form.querySelector("button[type=submit]");
  btn.disabled = true;
  try {
    const d = await api("PUT", "/api/routing", collectRouting(form.router_id.value));
    fillRoutingForms(d.config);
    ok.textContent = "Применено";
    loadRouting().catch(console.error);
  } catch (e) { err.textContent = e.message; }
  finally { btn.disabled = false; }
}));

// ---------------------------------------------------------------- Tools
const ms = (v) => v == null ? "—" : `${v} мс`;
const statusCell = (s) => s === "ok" || s === "open" ? `<span class="flag-r">${s === "ok" ? "ответ" : "открыт"}</span>`
  : `<span class="flag-x">${esc(s === "timeout" ? "нет ответа" : s === "closed" ? "закрыт" : s)}</span>`;

const PORT_STATUS = { open: '<span class="flag-r">открыт</span>', closed: '<span class="hint">закрыт</span>',
                      filtered: '<span class="flag-x">нет ответа</span>' };
const TOOLS = {
  ping: {
    fields: ["host", "family", "count", "interface"],
    hint: "ICMP echo. Узел может не отвечать на ping и при этом работать — проверьте его сканером портов.",
    cols: ["#", "От", "TTL", "Время", "Статус"],
    row: (r) => [r.seq, esc(r.from ?? "—"), r.ttl ?? "—", ms(r.time_ms), statusCell(r.status)],
    summary: (d) => `Отправлено ${d.sent ?? "—"}, получено ${d.received ?? "—"}, потери ${d.loss ?? "—"}%`
      + (d.avg != null ? ` · мин/сред/макс ${d.min}/${d.avg}/${d.max} мс` : ""),
  },
  port_scan: {
    fields: ["host", "ports", "interface"],
    hint: "Какие TCP-порты открыты на узле. Порты через запятую или диапазоном, до 1024 за раз; на больших диапазонах показываются только открытые.",
    cols: ["Порт", "Сервис", "Состояние", "Время"],
    row: (r) => [r.port, esc(r.service ?? ""), PORT_STATUS[r.status] ?? statusCell(r.status), ms(r.time_ms)],
    summary: (d) => `${d.host}${d.ip !== d.host ? ` (${d.ip})` : ""}: проверено ${d.scanned}, открыто ${d.open}, `
      + `закрыто ${d.closed}, без ответа ${d.filtered}`,
  },
  traceroute: {
    fields: ["host", "max_hops", "interface"],
    hint: "Путь пакета до узла (ICMP). «*» — узел не ответил: часто это фильтр, а не обрыв. Через VPN видны хопы внутри туннеля.",
    cols: ["Хоп", "Адрес", "Время 1", "Время 2", "Время 3", "Примечание"],
    row: (r) => [r.hop, esc(r.ip ?? "*") + (r.other_ips.length ? `<br><span class="hint">${r.other_ips.map(esc).join(", ")}</span>` : ""),
      ...[0, 1, 2].map((i) => r.times[i] == null ? "*" : `${r.times[i]} мс`), esc(r.notes.join(" "))],
  },
  dns: {
    fields: ["host"],
    hint: "Разрешение имени через DNS роутера — так же, как его видят устройства LAN (через туннель, если VPN «весь трафик»).",
    cols: ["Имя", "Адреса", "Время"],
  },
  neighbors: {
    fields: [],
    hint: "Таблица соседей ядра (ARP): кто в последнее время общался с роутером. Имена — из DHCP и закреплённых адресов.",
    cols: ["IP", "MAC", "Производитель", "Имя", "Интерфейс", "Состояние"],
    row: (r) => [esc(r.ip), esc(r.mac ?? "—"), esc(r.vendor ?? "—"), esc(r.name ?? "—"), esc(r.interface), esc(r.state ?? "")],
  },
  scan: {
    fields: ["network", "interface"],
    hint: "Какие устройства есть в сети: ping-обход + ARP — находит и тех, кто не отвечает на ping (телефоны, Windows).",
    cols: ["IP", "MAC", "Производитель", "Имя", "Ping", "Найден по"],
    row: (r) => [esc(r.ip), esc(r.mac ?? "—"), esc(r.vendor ?? "—"), esc(r.name ?? "—"), ms(r.ping_ms),
      r.source === "arp" ? "ARP" : "ping"],
    summary: (d) => `Сеть ${d.network}: проверено ${d.scanned}, найдено ${d.found}`,
  },
};

let tool = "ping";
let toolWs = null;
let toolInterfaces = null;

function toolBusy(busy) {
  $("#tool-start").disabled = busy;
  $("#tool-stop").disabled = !busy;
  $("#tool-status").textContent = busy ? "выполняется…" : "";
}

async function selectTool(name) {
  if (toolWs) toolWs.close();
  tool = name;
  const t = TOOLS[name];
  document.querySelectorAll("#tool-tabs .tab").forEach((x) => x.classList.toggle("active", x.dataset.tool === name));
  document.querySelectorAll("#tool-form [data-f]").forEach((l) => { l.hidden = !t.fields.includes(l.dataset.f); });
  $("#tool-hint").textContent = t.hint;
  $("#tool-head").innerHTML = `<tr>${t.cols.map((c) => `<th>${c}</th>`).join("")}</tr>`;
  $("#tool-rows").innerHTML = "";
  $("#tool-summary").hidden = true;
  $("#tool-error").textContent = "";
  $("#tool-start").textContent = name === "neighbors" ? "Обновить" : "Старт";
  toolBusy(false);
  if (!toolInterfaces) {
    try {
      toolInterfaces = await api("GET", "/api/tools/interfaces");
      const sel = $("#tool-form").interface;
      sel.innerHTML = '<option value="auto">авто</option>'
        + toolInterfaces.interfaces.map((i) => `<option>${esc(i)}</option>`).join("");
      $("#tool-form").network.value = toolInterfaces.scan_network ?? "";
    } catch (e) { console.error(e); }
  }
  $("#tool-form").interface.value = "auto";
  if (name === "neighbors") runTool();
}

function addToolRow(r) {
  const tr = document.createElement("tr");
  tr.innerHTML = TOOLS[tool].row(r).map((c) => `<td>${c}</td>`).join("");
  $("#tool-rows").appendChild(tr);
  if ($("#tool-rows").children.length > 2000) $("#tool-rows").firstChild.remove();
}

let summaryData = {};
function showSummary(d) {
  summaryData = { ...summaryData, ...d };
  const fn = TOOLS[tool].summary;
  if (!fn) return;
  $("#tool-summary").textContent = fn(summaryData);
  $("#tool-summary").hidden = false;
}

async function runTool() {
  const f = $("#tool-form");
  $("#tool-rows").innerHTML = "";
  $("#tool-error").textContent = "";
  $("#tool-summary").hidden = true;
  summaryData = {};

  if (tool === "neighbors") {
    try { (await api("GET", "/api/tools/neighbors")).forEach(addToolRow); }
    catch (e) { $("#tool-error").textContent = e.message; }
    return;
  }
  if (tool === "dns") {
    try {
      const d = await api("GET", `/api/tools/dns?host=${encodeURIComponent(f.host.value)}`);
      $("#tool-rows").innerHTML = `<tr><td>${esc(d.host)}</td><td>${d.error ? `<span class="flag-x">${esc(d.error)}</span>`
        : d.addresses.map(esc).join("<br>")}</td><td>${ms(d.time_ms)}</td></tr>`;
    } catch (e) { $("#tool-error").textContent = e.message; }
    return;
  }

  const params = {};
  TOOLS[tool].fields.forEach((name) => {
    params[name] = name === "family" ? f.querySelector("input[name=family]:checked").value : f[name].value;
  });
  const proto = location.protocol === "https:" ? "wss" : "ws";
  toolWs = new WebSocket(`${proto}://${location.host}/api/tools/ws`);
  toolBusy(true);
  toolWs.onopen = () => toolWs.send(JSON.stringify({ tool, params }));
  toolWs.onmessage = (m) => {
    const ev = JSON.parse(m.data);
    if (ev.type === "row") addToolRow(ev.row);
    else if (ev.type === "summary") showSummary(ev.data);
    else if (ev.type === "info") $("#tool-status").textContent = ev.text;
    else if (ev.type === "error") $("#tool-error").textContent = ev.text;
  };
  toolWs.onclose = () => { toolBusy(false); toolWs = null; };
}

$("#tool-tabs").addEventListener("click", (ev) => {
  const t = ev.target.closest(".tab");
  if (t) selectTool(t.dataset.tool);
});
$("#tool-form").addEventListener("submit", (ev) => { ev.preventDefault(); runTool(); });
$("#tool-stop").addEventListener("click", () => {
  if (toolWs && toolWs.readyState === WebSocket.OPEN) toolWs.send(JSON.stringify({ action: "stop" }));
});

// ---------------------------------------------------------------- System
let sysTab = "overview";

function selectSysTab(tab) {
  sysTab = tab;
  document.querySelectorAll("#sys-tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === tab));
  document.querySelectorAll("#page-system [data-panel]").forEach((p) => { p.hidden = p.dataset.panel !== tab; });
  if (location.hash === "#system") loadSystemPage().catch(console.error);
}
$("#sys-tabs").addEventListener("click", (ev) => {
  const t = ev.target.closest(".tab");
  if (t) selectSysTab(t.dataset.tab);
});

function duration(sec) {
  if (sec == null) return "—";
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return (d ? `${d} д ` : "") + `${h} ч ${m} мин`;
}

const tile = (label, value, pct) => `<div class="tile"><span class="label">${label}</span><b>${value}</b>`
  + (pct != null ? `<div class="bar"><i style="width:${Math.min(pct, 100)}%" class="${pct > 85 ? "hot" : ""}"></i></div>` : "")
  + "</div>";

async function loadSystemPage() {
  if (sysTab === "overview") {
    const r = await api("GET", "/api/system/resource");
    $("#sys-tiles").innerHTML =
      tile("CPU", r.cpu_percent == null ? "…" : `${r.cpu_percent}%`, r.cpu_percent)
      + tile("Память", `${fmt(r.memory.used)} / ${fmt(r.memory.total)}`, r.memory.percent)
      + tile("Диск", `${fmt(r.disk.used)} / ${fmt(r.disk.total)}`, r.disk.percent)
      + tile("Uptime", duration(r.uptime))
      + (r.temperature != null ? tile("Температура", `${r.temperature} °C`, r.temperature) : "");
    const row = (k, v) => `<div><span class="label">${k}</span><span>${esc(v ?? "—")}</span></div>`;
    $("#sys-info").innerHTML = row("Устройство", r.model) + row("Архитектура", `${r.arch}, ${r.cpu_count} CPU`)
      + row("Ядро", r.kernel) + row("Версия", r.version) + row("Режим", r.mode) + row("Hostname", r.hostname)
      + row("Нагрузка", r.load.join(" / ")) + row("Время", new Date(r.time).toLocaleString(I18N.locale()));
    const f = $("#identity-form");
    if (document.activeElement !== f.identity) f.identity.value = r.identity;
  } else if (sysTab === "users") {
    const users = await api("GET", "/api/system/users");
    $("#users").innerHTML = users.map((u) => `
      <tr><td><b>${esc(u.name)}</b>${u.name === me.name ? ' <span class="hint">(вы)</span>' : ""}</td>
        <td><select data-role="${esc(u.name)}"><option value="full" ${u.role === "full" ? "selected" : ""}>Полные права</option>
          <option value="read" ${u.role === "read" ? "selected" : ""}>Только просмотр</option></select></td>
        <td>${!u.has_password ? '<span class="flag-x">не задан</span>'
          : u.must_change ? '<span class="flag-x">сменит при входе</span>' : "задан"}</td>
        <td class="actions">${u.name === me.name ? '<button type="button" data-own="1">Сменить пароль</button>'
          : `<button type="button" data-reset="${esc(u.name)}">Новый пароль</button>
             <button type="button" data-udel="${esc(u.name)}" class="danger">Удалить</button>`}</td></tr>`).join("");
  } else if (sysTab === "backup") {
    const snaps = await api("GET", "/api/system/snapshots");
    $("#snapshots").innerHTML = snaps.map((x) => `
      <tr><td>${new Date(x.time).toLocaleString(I18N.locale())}</td><td>${fmt(x.size)}</td>
        <td class="actions"><a href="/api/system/snapshots/${encodeURIComponent(x.name)}">скачать</a>
          <button type="button" data-snap="${esc(x.name)}">Восстановить</button></td></tr>`).join("")
      || '<tr><td colspan="3" class="hint">снимков пока нет — они появятся после первого изменения</td></tr>';
  } else if (sysTab === "audit") {
    const log = await api("GET", "/api/system/audit?limit=300");
    $("#audit").innerHTML = log.map((x) => `
      <tr class="${x.status >= 400 ? "row-inactive" : ""}"><td>${new Date(x.time).toLocaleString(I18N.locale())}</td><td>${esc(x.user)}</td>
        <td>${esc(x.method)}</td><td class="mono">${esc(x.path)}</td><td>${x.status}</td><td>${esc(x.ip)}</td></tr>`).join("")
      || '<tr><td colspan="6" class="hint">записей нет</td></tr>';
  }
}

$("#identity-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const r = await api("PUT", "/api/system/identity", { identity: ev.target.identity.value });
    setIdentity(r.identity);
    $("#identity-msg").textContent = "Сохранено";
  } catch (e) { $("#identity-msg").textContent = e.message; }
});

$("#restart-btn").addEventListener("click", async () => {
  if (!confirm(I18N.t("Перезапустить сервис роутера? Связь пропадёт на несколько секунд."))) return;
  const r = await api("POST", "/api/system/restart");
  $("#restart-msg").textContent = r.message;
  setTimeout(() => location.reload(), 8000);
});

$("#users").addEventListener("change", async (ev) => {
  const sel = ev.target.closest("select[data-role]");
  if (!sel) return;
  try { await api("PUT", `/api/system/users/${sel.dataset.role}`, { role: sel.value }); }
  catch (e) { alert(I18N.tr(e.message)); }
  loadSystemPage();
});

$("#users").addEventListener("click", async (ev) => {
  const b = ev.target.closest("button");
  if (!b) return;
  try {
    if (b.dataset.own) { openPwChange(); return; }
    if (b.dataset.reset) {
      const pw = prompt(I18N.t("Временный пароль для {user} (не короче 8 символов). Пользователь сменит его при входе:", { user: b.dataset.reset }));
      if (pw) await api("PUT", `/api/system/users/${b.dataset.reset}`, { password: pw });
    }
    if (b.dataset.udel && confirm(I18N.t("Удалить пользователя {name}?", { name: b.dataset.udel }))) {
      await api("DELETE", `/api/system/users/${b.dataset.udel}`);
    }
  } catch (e) { alert(I18N.tr(e.message)); }
  loadSystemPage();
});

$("#user-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("#user-error").textContent = "";
  try {
    await api("POST", "/api/system/users", { name: f.name.value, password: f.password.value, role: f.role.value });
    f.reset();
    loadSystemPage();
  } catch (e) { $("#user-error").textContent = e.message; }
});

$("#restore-btn").addEventListener("click", async () => {
  const file = $("#restore-file").files[0];
  $("#restore-msg").textContent = "";
  $("#restore-error").textContent = "";
  if (!file) { $("#restore-error").textContent = "выберите файл .yaml"; return; }
  if (!confirm(I18N.t("Заменить текущую конфигурацию роутера содержимым файла? Текущая версия сохранится в снимках."))) return;
  try {
    await api("POST", "/api/system/restore", { text: await file.text(), filename: file.name });
    $("#restore-msg").textContent = "Восстановлено и применено";
    loadSystemPage();
  } catch (e) { $("#restore-error").textContent = e.message; }
});

$("#snapshots").addEventListener("click", async (ev) => {
  const b = ev.target.closest("button[data-snap]");
  if (!b || !confirm(I18N.t("Вернуть конфигурацию из этого снимка? Текущая версия тоже сохранится в снимках."))) return;
  try {
    await api("POST", `/api/system/snapshots/${encodeURIComponent(b.dataset.snap)}/restore`);
    $("#restore-msg").textContent = "Снимок восстановлен и применён";
    loadSystemPage();
  } catch (e) { $("#restore-error").textContent = e.message; }
});

// ---------------------------------------------------------------- навигация
const pages = {
  "status": loadStatus,
  "wan": loadWan,
  "lan": loadLan,
  "vpn": loadVpn,
  "firewall": loadFirewall,
  "routing": loadRouting,
  "tools": async () => {},          // инструменты обновляются сами, без опроса
  "system": () => (sysTab === "overview" ? loadSystemPage() : Promise.resolve()),
};
let timer = null;

function show() {
  const page = pages[location.hash.slice(1)] ? location.hash.slice(1) : "status";
  document.querySelectorAll(".page").forEach((p) => p.classList.toggle("active", p.id === `page-${page}`));
  document.querySelectorAll("nav a[data-page]").forEach((a) => a.classList.toggle("active", a.dataset.page === page));
  clearInterval(timer);
  const load = () => pages[page]().catch((e) => console.error(e));
  load();
  timer = setInterval(load, 3000);
}

// ---------------------------------------------------------------- Вход
let me = null;
let appStarted = false;

function showLogin() {
  clearInterval(timer);
  $("#pwchange").hidden = true;
  $("#login").hidden = false;
  $("#login-form").password.focus();
}

async function checkAuth() {
  me = await api("GET", "/api/auth/me");
  if (!me.logged_in) return showLogin();
  $("#pwchange-cancel").hidden = me.must_change;
  $("#nopw-banner").hidden = me.has_password;
  if (me.must_change) { $("#login").hidden = true; openPwChange(); return; }
  $("#login").hidden = true;
  $("#pwchange").hidden = true;
  $("#whoami").textContent = `${me.name}${me.role === "read" ? " (просмотр)" : ""}`;
  setIdentity(me.identity);
  startApp();
}

function setIdentity(name) {
  $("#identity").textContent = name;
  document.title = `${name} — OutpostGate Pro`;
}

function startApp() {
  if (appStarted) { show(); return; }
  appStarted = true;
  window.addEventListener("hashchange", show);
  selectVpnTab("wireguard");
  selectFwTab("input");
  selectRtTab("overview");
  selectTool("ping");
  selectSysTab("overview");
  loadSystem().catch(console.error);
  show();
  pollSafeMode();
  setInterval(pollSafeMode, 3000);
}

$("#login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("#login-error").textContent = "";
  try {
    await api("POST", "/api/auth/login", { name: f.name.value, password: f.password.value });
    f.password.value = "";
    await checkAuth();
  } catch (e) { $("#login-error").textContent = e.message; }
});

$("#pwchange-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("#pwchange-error").textContent = "";
  if (f.new.value !== f.new2.value) { $("#pwchange-error").textContent = "пароли не совпадают"; return; }
  try {
    await api("POST", "/api/auth/password", { old: me && !me.has_password ? "" : f.old.value, new: f.new.value });
    f.reset();
    await checkAuth();
  } catch (e) { $("#pwchange-error").textContent = e.message; }
});

function openPwChange() {
  const first = me && !me.has_password;
  $("#pwchange-title").textContent = first ? "Задайте пароль" : "Смените пароль";
  $("#pwchange-hint").textContent = first
    ? "Сейчас вход без пароля. Задайте пароль администратора — не короче 8 символов."
    : me && me.must_change ? "Пароль был выдан администратором — задайте свой (не короче 8 символов)."
    : "Новый пароль — не короче 8 символов. Остальные сессии будут завершены.";
  $("#pwchange-old").hidden = first;
  $("#pwchange").hidden = false;
}

$("#nopw-set").addEventListener("click", openPwChange);

$("#pwchange-cancel").addEventListener("click", () => {
  if (me && me.logged_in && !me.must_change) $("#pwchange").hidden = true;   // при обязательной смене — нельзя
});

$("#logout").addEventListener("click", async (ev) => {
  ev.preventDefault();
  await api("POST", "/api/auth/logout");
  location.reload();
});

// ---------------------------------------------------------------- Safe Mode
let safeActive = false;
let safeEventShown = null;

async function pollSafeMode() {
  let st;
  try { st = await api("GET", "/api/system/safe-mode"); } catch (_) { return; }
  safeActive = st.active;
  $("#safe-btn").classList.toggle("on", st.active);
  $("#safe-btn").textContent = st.active ? "Safe Mode ●" : "Safe Mode";
  $("#safe-banner").hidden = !st.active;
  if (st.active) {
    $("#safe-text").textContent = `включил ${st.user}. Если связь с роутером пропадёт на ${st.timeout} с, `
      + "конфигурация вернётся к состоянию до включения. Пока страница открыта — связь есть.";
  }
  const ev = st.last_event;
  if (ev && ev.type === "rollback" && ev.time !== safeEventShown) {
    safeEventShown = ev.time;
    $("#safe-event").textContent = `Safe Mode: конфигурация откачена (${ev.reason}) — ${new Date(ev.time).toLocaleString(I18N.locale())}`;
    $("#safe-event").hidden = false;
  }
}

async function safeStart() {
  const timeout = Number($("#safe-timeout").value || 60);
  try { await api("POST", "/api/system/safe-mode", { timeout }); } catch (e) { alert(I18N.tr(e.message)); }
  pollSafeMode();
}

$("#safe-btn").addEventListener("click", async () => {
  if (safeActive) { try { await api("POST", "/api/system/safe-mode/commit"); } catch (e) { alert(I18N.tr(e.message)); } }
  else await safeStart();
  pollSafeMode();
});
$("#safe-start2").addEventListener("click", safeStart);
$("#safe-commit").addEventListener("click", async () => { await api("POST", "/api/system/safe-mode/commit"); pollSafeMode(); });
$("#safe-rollback").addEventListener("click", async () => {
  if (!confirm(I18N.t("Вернуть конфигурацию к состоянию до включения Safe Mode?"))) return;
  await api("POST", "/api/system/safe-mode/rollback");
  pollSafeMode();
});
$("#safe-event").addEventListener("click", () => { $("#safe-event").hidden = true; });

checkAuth().catch((e) => { console.error(e); showLogin(); });
