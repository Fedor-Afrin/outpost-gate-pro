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
        ...(w.wans ?? []).map((x) => [x.name, `${esc(x.interface ?? "—")} · ${x.healthy === false ? I18N.t("нет связи")
          : x.healthy ? I18N.t("работает") : "…"}${x.active ? " · " + I18N.t("трафик") : ""}`]),
        w.wans?.length ? ["Режим двух WAN", w.multi_mode === "balance" ? "балансировка" : "резерв"] : null,
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
  f.vlan_id.value = c.vlan_id ?? "";
  wanModeChanged();
}

let wanTab = "wan1";
let wan2FormLoaded = false;
let mwFormLoaded = false;

function selectWanTab(tab) {
  wanTab = tab;
  document.querySelectorAll("#wan-tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === tab));
  for (const t of ["wan1", "wan2", "multi"]) $(`#wan-p-${t}`).hidden = t !== tab;
  if (location.hash === "#wan") loadWan().catch(console.error);
}
$("#wan-tabs").addEventListener("click", (ev) => { const t = ev.target.closest(".tab"); if (t) selectWanTab(t.dataset.tab); });

async function loadWan() {
  if (wanTab === "wan2") return loadWan2();
  if (wanTab === "multi") return loadMultiWan();
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
      vlan_id: f.get("vlan_id") ? Number(f.get("vlan_id")) : null,
    });
    fillWanForm(w);
    $("#wan-ok").textContent = "Применено";
    await loadWan();
  } catch (e) {
    $("#wan-error").textContent = e.message;
  }
});

// --- WAN2: второй провайдер
function wan2ModeChanged() {
  const mode = $("#wan2-form").querySelector("input[name=mode]:checked")?.value;
  $("#wan2-static").hidden = mode !== "static";
}
$("#wan2-form").addEventListener("change", (ev) => { if (ev.target.name === "mode") wan2ModeChanged(); });

function fillWan2Form(w) {
  const f = $("#wan2-form"), c = w.config;
  const opts = [...w.interfaces];
  if (c.interface && !opts.includes(c.interface)) opts.push(c.interface);
  $("#wan2-iface").innerHTML = '<option value="">—</option>' + opts.map((n) =>
    `<option value="${esc(n)}" ${n === c.interface ? "selected" : ""}>${esc(n)}</option>`).join("");
  f.enabled.checked = !!c.enabled;
  const mode = c.mode === "static" ? "static" : "dhcp";
  f.querySelector(`input[name=mode][value=${mode}]`).checked = true;
  f.address.value = c.address ?? "";
  f.gateway.value = c.gateway ?? "";
  f.dns1.value = c.dns[0] ?? "";
  f.dns2.value = c.dns[1] ?? "";
  f.vlan_id.value = c.vlan_id ?? "";
  wan2ModeChanged();
}

async function loadWan2() {
  const w = await api("GET", "/api/wan/wan2");
  const on = !!w.config.enabled;
  $("#w2-iface").textContent = on ? (w.interface ?? "—") : "выключен";
  $("#w2-link").innerHTML = !on ? "—" : w.link_up ? '<span class="flag-r">есть</span>' : '<span class="flag-x">нет кабеля</span>';
  $("#w2-state").textContent = on ? (STATE_TEXT[w.dhcp_state] ?? (w.dhcp_state || "—")) : "—";
  $("#w2-addr").innerHTML = on && w.addresses.length ? w.addresses.map(esc).join("<br>") : "—";
  $("#w2-gw").textContent = on ? (w.gateway ?? "—") : "—";
  $("#w2-dns").textContent = on && w.dns.length ? w.dns.join(", ") : "—";
  $("#wan2-renew").hidden = !w.dhcp_running;
  if (!wan2FormLoaded) { fillWan2Form(w); wan2FormLoaded = true; }
}

$("#wan2-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const mode = f.get("mode");
  $("#wan2-error").textContent = ""; $("#wan2-ok").textContent = "";
  try {
    const w = await api("PUT", "/api/wan/wan2", {
      enabled: ev.target.enabled.checked, interface: f.get("interface") || "", mode,
      address: mode === "static" ? f.get("address") || null : null,
      gateway: mode === "static" ? f.get("gateway") || null : null,
      dns: [f.get("dns1"), f.get("dns2")].filter(Boolean),
      vlan_id: f.get("vlan_id") ? Number(f.get("vlan_id")) : null,
    });
    fillWan2Form(w);
    $("#wan2-ok").textContent = "Применено";
    await loadWan2();
  } catch (e) { $("#wan2-error").textContent = e.message; }
});

$("#wan2-renew").addEventListener("click", async () => {
  try { await api("POST", "/api/wan/wan2/renew"); await loadWan2(); }
  catch (e) { $("#wan2-error").textContent = e.message; }
});

// --- два провайдера: резерв или балансировка
function mwModeChanged() {
  const mode = $("#mw-form").querySelector("input[name=mode]:checked")?.value;
  $("#mw-failover").hidden = mode !== "failover";
  $("#mw-balance").hidden = mode !== "balance";
}
$("#mw-form").addEventListener("change", (ev) => { if (ev.target.name === "mode") mwModeChanged(); });

function fillMwForm(c) {
  const f = $("#mw-form");
  f.querySelector(`input[name=mode][value=${c.mode}]`).checked = true;
  f.primary.value = c.primary;
  f.weight1.value = c.weight1; f.weight2.value = c.weight2;
  f.check_targets.value = c.check_targets.join(", ");
  f.interval.value = c.interval; f.fail_after.value = c.fail_after; f.recover_after.value = c.recover_after;
  mwModeChanged();
}

const mwCheck = (h) => (h === true ? '<span class="dot ok"></span> есть' : h === false ? '<span class="dot bad"></span> нет связи' : "—");

async function loadMultiWan() {
  const d = await api("GET", "/api/wan/multiwan");
  $("#mw-off").hidden = d.enabled;
  const rows = d.wans.filter((w) => w.enabled);
  $("#mw-wans").innerHTML = rows.map((w) => `<tr><td><b>${esc(w.name)}</b></td><td>${dash(w.interface)}</td>
    <td>${dash(w.address)}</td><td>${dash(w.gateway)}</td><td>${d.enabled ? mwCheck(w.healthy) : "—"}</td>
    <td class="num">${w.rtt != null ? esc(I18N.t("{v} мс", { v: w.rtt })) : "—"}</td>
    <td>${w.active ? '<span class="badge lan">активный</span>' : d.enabled ? '<span class="badge port">запасной</span>' : "—"}</td>
    <td>${w.since ? new Date(w.since * 1000).toLocaleString(I18N.locale()) : "—"}</td></tr>`).join("");
  $("#mw-events").innerHTML = d.events.map((e) => `<tr><td>${new Date(e.time * 1000).toLocaleString(I18N.locale())}</td>
    <td>${esc(e.wan.toUpperCase())} — ${e.state === "down" ? "упал" : "вернулся"}</td>
    <td>${esc(e.active.map((x) => x.toUpperCase()).join(", ") || "—")}</td></tr>`).join("")
    || '<tr><td colspan="3" class="hint">переключений не было</td></tr>';
  if (!mwFormLoaded) { fillMwForm(d.config); mwFormLoaded = true; }
}

$("#mw-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("#mw-error").textContent = ""; $("#mw-ok").textContent = "";
  try {
    const d = await api("PUT", "/api/wan/multiwan", {
      mode: f.querySelector("input[name=mode]:checked").value, primary: f.primary.value,
      weight1: Number(f.weight1.value), weight2: Number(f.weight2.value),
      check_targets: f.check_targets.value.split(/[\s,;]+/).filter(Boolean),
      interval: Number(f.interval.value), fail_after: Number(f.fail_after.value), recover_after: Number(f.recover_after.value),
    });
    fillMwForm(d.config);
    $("#mw-ok").textContent = "Применено";
    await loadMultiWan();
  } catch (e) { $("#mw-error").textContent = e.message; }
});

$("#wan-renew").addEventListener("click", async () => {
  try { await api("POST", "/api/wan/renew"); await loadWan(); }
  catch (e) { $("#wan-error").textContent = e.message; }
});

// ---------------------------------------------------------------- LAN: сегменты
const ROLE = { wan: '<span class="badge wan">WAN</span>', lan: '<span class="badge lan">LAN</span>', none: "—" };
let lanSeg = "lan1";            // выбранный сегмент; "new" — добавление
let lanFormFor = null;          // для какого сегмента заполнена форма (опрос не трогает ввод)
let lanData = null;
const csv = (a) => (a || []).join(", ");
const items = (s) => s.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
const segName = (id) => (lanData?.segments.find((s) => s.config.id === id)?.config.name) || id;

function segTabs(box, current, segs, withNew) {
  $(box).innerHTML = segs.map((s) => `<a class="tab ${s.id === current ? "active" : ""}" data-seg="${esc(s.id)}">${esc(s.name)}</a>`).join("")
    + (withNew ? `<a class="tab ${current === "new" ? "active" : ""}" data-seg="new">+ Сегмент</a>` : "");
}

function lanPortsAutoChanged() {
  const f = $("#lan-form");
  const auto = lanSeg === "lan1" && f.ports_auto.checked;
  $("#lan-port-list").querySelectorAll("input").forEach((i) => { if (!i.dataset.busy) i.disabled = auto; });
}

function newSegmentConfig(n) {
  const third = 88 + n;
  return { id: "new", name: `LAN${n + 1}`, enabled: true, address: `192.168.${third}.1/24`, ports: [], dns_enabled: true,
           domain: lanData?.segments[0]?.config.domain || "office.lan", forward_to: [], dhcp_enabled: true,
           pool_start: null, pool_end: null, lease_time: "12h", wan_management: true, dhcp_options: {} };
}

function fillLanForm() {
  const f = $("#lan-form");
  const segs = lanData.segments;
  const seg = segs.find((s) => s.config.id === lanSeg);
  const c = seg ? seg.config : newSegmentConfig(segs.length);
  const primary = lanSeg === "lan1";
  $("#lan-form-title").textContent = lanSeg === "new" ? "Новый сегмент" : "Настройки";
  f.enabled.checked = c.enabled;
  f.name.value = c.name;
  f.address.value = c.address;
  $("#lan-auto-label").hidden = !primary;
  f.ports_auto.checked = primary && c.ports.length === 0;
  // порты: свободные, свои и занятые другими сегментами (их нельзя выбрать)
  const owner = {};
  lanData.ports.forEach((p) => { if (p.segment) owner[p.name] = p.segment; });
  segs.forEach((s) => (s.config.ports || []).forEach((p) => { if (s.config.id !== "lan1") owner[p] = s.config.id; }));
  $("#lan-port-list").innerHTML = lanData.ports.filter((p) => p.role !== "wan").map((p) => {
    const other = owner[p.name] && owner[p.name] !== lanSeg && !(primary && owner[p.name] === "lan1");
    const busy = other && owner[p.name] !== "lan1";
    const mine = c.ports.includes(p.name) || (primary && c.ports.length === 0 && !busy);
    return `<label class="check"><input type="checkbox" name="port" value="${esc(p.name)}" ${mine ? "checked" : ""}
      ${busy ? 'disabled data-busy="1"' : ""}> ${esc(p.name)}${busy ? ` <span class="hint">(${esc(segName(owner[p.name]))})</span>` : ""}</label>`;
  }).join("") || '<span class="hint">нет свободных портов</span>';
  f.vlan_id.value = c.vlan_id ?? "";
  const trunkCandidates = lanData.ports.filter((p) => !p.name.includes("."));
  $("#lan-trunk-list").innerHTML = trunkCandidates.map((p) => `<label class="check"><input type="checkbox" name="trunk" value="${esc(p.name)}"
    ${(c.trunk_ports || []).includes(p.name) ? "checked" : ""}> ${esc(p.name)}${p.role === "wan" ? ' <span class="hint">(WAN)</span>' : ""}</label>`).join("")
    || '<span class="hint">нет портов</span>';
  f.dns_enabled.checked = c.dns_enabled;
  f.domain.value = c.domain ?? "";
  $("#lan-forward").innerHTML = segs.filter((s) => s.config.id !== lanSeg).map((s) => `
    <label class="check"><input type="checkbox" name="forward_to" value="${esc(s.config.id)}"
      ${c.forward_to.includes(s.config.id) ? "checked" : ""}> → ${esc(s.config.name)} (${esc(s.config.address)})</label>`).join("")
    || '<span class="hint">других сегментов нет</span>';
  $("#lan-wan-block").hidden = !primary;
  f.wan_management.checked = c.wan_management;
  $("#lan-delete").hidden = primary || lanSeg === "new";
  $("#lan-main-hint").hidden = !primary;
  lanPortsAutoChanged();
  lanFormFor = lanSeg;
}

async function loadLan() {
  const l = await api("GET", "/api/lan");
  lanData = l;
  if (lanSeg !== "new" && !l.segments.some((s) => s.config.id === lanSeg)) lanSeg = "lan1";
  segTabs("#lan-tabs", lanSeg, l.segments.map((s) => s.config), true);
  const seg = l.segments.find((s) => s.config.id === lanSeg);
  $("#ls-state").innerHTML = !seg ? "—" : seg.active ? '<span class="flag-r">работает</span>'
    : (seg.config.enabled ? '<span class="flag-x">ошибка — см. docker logs</span>' : "выключен");
  $("#ls-bridge").textContent = seg ? seg.bridge : "—";
  $("#ls-addr").textContent = seg && seg.active ? seg.config.address : "—";
  $("#ls-clients").textContent = seg ? seg.clients : "—";
  $("#lan-ports").innerHTML = l.ports.map((p) => `
    <tr><td>${esc(p.name)}</td><td>${ROLE[p.role]}</td><td>${p.segment ? esc(segName(p.segment)) : "—"}</td>
        <td>${(p.vlans || []).map(esc).join(", ") || "—"}</td>
        <td>${p.link_up ? '<span class="flag-r">есть</span>' : '<span class="flag-x">нет</span>'}</td>
        <td>${esc(p.mac)}</td></tr>`).join("");
  if (lanFormFor !== lanSeg) fillLanForm();
}

$("#lan-tabs").addEventListener("click", (ev) => {
  const t = ev.target.closest(".tab");
  if (!t) return;
  lanSeg = t.dataset.seg;
  lanFormFor = null;
  $("#lan-error").textContent = ""; $("#lan-ok").textContent = "";
  loadLan().catch(console.error);
});

$("#lan-form").addEventListener("change", (ev) => { if (ev.target.name === "ports_auto") lanPortsAutoChanged(); });

function ipNet(cidr) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec((cidr || "").trim());
  if (!m) return null;
  const ip = ((+m[1] << 24) | (+m[2] << 16) | (+m[3] << 8) | +m[4]) >>> 0;
  const bits = +m[5], mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return `${(ip & mask) >>> 0}/${bits}`;
}

$("#lan-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("#lan-error").textContent = ""; $("#lan-ok").textContent = "";
  const seg = lanData.segments.find((s) => s.config.id === lanSeg);
  const base = seg ? seg.config : newSegmentConfig(lanData.segments.length);
  const ports = lanSeg === "lan1" && f.ports_auto.checked ? []
    : [...f.querySelectorAll("input[name=port]:checked:not(:disabled)")].map((i) => i.value);
  const body = { ...base, id: lanSeg === "new" ? "lan2" : lanSeg, enabled: f.enabled.checked, name: f.name.value.trim(),
    address: f.address.value.trim(), ports, dns_enabled: f.dns_enabled.checked, domain: f.domain.value.trim() || null,
    forward_to: [...f.querySelectorAll("input[name=forward_to]:checked")].map((i) => i.value),
    vlan_id: f.vlan_id.value ? Number(f.vlan_id.value) : null,
    trunk_ports: [...f.querySelectorAll("input[name=trunk]:checked")].map((i) => i.value),
    wan_management: lanSeg === "lan1" ? f.wan_management.checked : base.wan_management };
  try {
    if (lanSeg === "new") {
      const segs = await api("POST", "/api/lan/segments", body);
      lanSeg = segs[segs.length - 1].config.id;
    } else if (lanSeg === "lan1") {
      await api("PUT", "/api/lan", body);
    } else {
      await api("PUT", `/api/lan/segments/${lanSeg}`, body);
    }
    lanFormFor = null;
    const moved = seg && ipNet(base.address) !== ipNet(body.address);
    $("#lan-ok").textContent = moved
      ? I18N.t("Применено: сеть изменена, диапазон DHCP и закреплённые адреса перенесены в новую сеть")
      : "Применено";
    await loadLan();
  } catch (e) { $("#lan-error").textContent = e.message; }
});

$("#lan-delete").addEventListener("click", async () => {
  if (!confirm(I18N.t("Удалить сегмент {name}? Его порты вернутся в основной LAN.", { name: segName(lanSeg) }))) return;
  try {
    await api("DELETE", `/api/lan/segments/${lanSeg}`);
    lanSeg = "lan1"; lanFormFor = null;
    await loadLan();
  } catch (e) { $("#lan-error").textContent = e.message; }
});

// ---------------------------------------------------------------- DHCP (Kea)
let dhcpSeg = "lan1";
let dhcpFormFor = null;
let dhcpData = null;
const CUSTOM_TYPES = ["ip", "text", "hex", "uint8", "uint16", "uint32", "bool"];

function customRow(c = {}) {
  const types = CUSTOM_TYPES.map((t) => `<option ${t === (c.type || "text") ? "selected" : ""}>${t}</option>`).join("");
  return `<tr data-row="custom"><td>${inp("code", c.code, 'type="number" min="1" max="254" class="narrow"')}</td>
    <td><select name="type">${types}</select></td><td>${inp("value", c.value, 'size="28"')}</td>
    <td>${inp("comment", c.comment, 'size="18"')}</td>
    <td><button type="button" class="danger" data-del-row>×</button></td></tr>`;
}

function fillDhcpForm(seg) {
  const f = $("#dhcp-form");
  const s = seg.settings, o = s.dhcp_options;
  f.dhcp_enabled.checked = s.dhcp_enabled;
  f.pool_start.value = s.pool_start ?? "";
  f.pool_end.value = s.pool_end ?? "";
  f.lease_time.value = s.lease_time;
  if (!f.lease_time.value) f.lease_time.add(new Option(s.lease_time, s.lease_time, true, true));
  for (const k of ["dns_servers", "domain_search", "ntp_servers", "wins_servers", "tftp_servers_150", "sip_servers", "static_routes"]) {
    f[k].value = csv(o[k]);
  }
  for (const k of ["time_offset", "mtu", "tftp_server", "boot_file", "provisioning_url", "wpad_url", "vendor_43"]) {
    f[k].value = o[k] ?? "";
  }
  $("#dhcp-custom").innerHTML = (o.custom || []).map(customRow).join("");
  dhcpFormFor = seg.id;
}

function renderStatic(list) {
  $("#static-leases").innerHTML = list.map((x) => `
    <tr class="${x.valid ? "" : "row-inactive"}"><td>${esc(x.name ?? "—")}</td><td>${esc(x.ip)}</td><td>${esc(x.mac)}</td>
      <td>${!x.valid ? "вне сети LAN — не работает" : x.in_pool ? "внутри пула DHCP" : ""}</td>
      <td class="actions"><button type="button" data-wol="${esc(x.mac)}">Разбудить</button>
        <button type="button" data-unpin="${esc(x.mac)}" class="danger">Открепить</button></td></tr>`).join("")
    || '<tr><td colspan="5" class="hint">нет</td></tr>';
}

async function loadDhcp() {
  const d = await api("GET", "/api/dhcp");
  dhcpData = d;
  if (!d.segments.some((s) => s.id === dhcpSeg)) dhcpSeg = "lan1";
  segTabs("#dhcp-tabs", dhcpSeg, d.segments, false);
  const seg = d.segments.find((s) => s.id === dhcpSeg);
  $("#dh-state").innerHTML = !d.installed ? '<span class="flag-x">нет в образе</span>'
    : d.running ? '<span class="flag-r">работает</span>' : "выключен";
  $("#dh-net").textContent = `${seg.network} (${seg.bridge})` + (seg.enabled ? "" : " · сегмент выключен");
  $("#dh-domain").textContent = seg.domain || "—";
  $("#dh-dns").textContent = seg.settings.dhcp_options.dns_servers?.length ? csv(seg.settings.dhcp_options.dns_servers)
    : seg.dns_enabled ? `роутер (${seg.address.split("/")[0]})` : "DNS провайдера";
  $("#dh-error").textContent = d.error || "";
  renderStatic(seg.static_leases);
  const leases = d.leases.filter((l) => l.lan === dhcpSeg);
  $("#lan-leases").innerHTML = leases.map((x) => `
    <tr><td>${esc(x.name ?? x.hostname ?? "—")}</td><td>${esc(x.ip)}</td><td>${esc(x.mac)}</td>
        <td>${esc(x.vendor ?? "—")}</td>
        <td>${x.expires ? new Date(x.expires * 1000).toLocaleString(I18N.locale()) : "бессрочно"}</td>
        <td class="actions"><button type="button" data-wol="${esc(x.mac)}">Разбудить</button>
          ${x.static ? '<span class="badge lan">закреплён</span>'
          : `<button type="button" data-pin="${esc(x.mac)}" data-ip="${esc(x.ip)}" data-name="${esc(x.hostname ?? "")}">Закрепить</button>`}</td></tr>`).join("")
    || '<tr><td colspan="6" class="hint">пока никого</td></tr>';
  if (dhcpFormFor !== dhcpSeg) fillDhcpForm(seg);
}

// Wake-on-LAN из списков DHCP
async function wakeUp(mac, lanId, okBox, errBox) {
  okBox.textContent = ""; errBox.textContent = "";
  try {
    const r = await api("POST", "/api/tools/wol", { mac, lan: lanId || null });
    okBox.textContent = I18N.t("Пакет пробуждения отправлен на {mac} ({where})", { mac: r.mac, where: r.sent.map((x) => x.name).join(", ") });
  } catch (e) { errBox.textContent = e.message; }
}
document.querySelector("#page-dhcp").addEventListener("click", (ev) => {
  const b = ev.target.closest("button[data-wol]");
  if (b) wakeUp(b.dataset.wol, dhcpSeg, $("#dh-wol-ok"), $("#dh-wol-error"));
});

$("#dhcp-tabs").addEventListener("click", (ev) => {
  const t = ev.target.closest(".tab");
  if (!t) return;
  dhcpSeg = t.dataset.seg; dhcpFormFor = null;
  ["#dhcp-form-error", "#dhcp-form-ok", "#static-error"].forEach((x) => { $(x).textContent = ""; });
  loadDhcp().catch(console.error);
});

$("#dhcp-custom-add").addEventListener("click", () => $("#dhcp-custom").insertAdjacentHTML("beforeend", customRow()));
$("#dhcp-custom").addEventListener("click", (ev) => { const b = ev.target.closest("[data-del-row]"); if (b) b.closest("tr").remove(); });

$("#dhcp-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("#dhcp-form-error").textContent = ""; $("#dhcp-form-ok").textContent = "";
  const v = (k) => opt(f[k].value);
  const body = {
    dhcp_enabled: f.dhcp_enabled.checked, pool_start: v("pool_start"), pool_end: v("pool_end"), lease_time: f.lease_time.value,
    dhcp_options: {
      dns_servers: items(f.dns_servers.value), domain_search: items(f.domain_search.value),
      ntp_servers: items(f.ntp_servers.value), wins_servers: items(f.wins_servers.value),
      tftp_servers_150: items(f.tftp_servers_150.value), sip_servers: items(f.sip_servers.value),
      static_routes: f.static_routes.value.split(",").map((x) => x.trim()).filter(Boolean),
      time_offset: num(f.time_offset.value), mtu: num(f.mtu.value),
      tftp_server: v("tftp_server"), boot_file: v("boot_file"), provisioning_url: v("provisioning_url"),
      wpad_url: v("wpad_url"), vendor_43: v("vendor_43"),
      custom: [...$("#dhcp-custom").querySelectorAll("[data-row]")].map((r) => ({
        code: num(r.querySelector("[name=code]").value), type: r.querySelector("[name=type]").value,
        value: r.querySelector("[name=value]").value, comment: opt(r.querySelector("[name=comment]").value),
      })).filter((c) => c.code),
    },
  };
  try {
    const d = await api("PUT", `/api/dhcp/${dhcpSeg}`, body);
    fillDhcpForm(d.segments.find((s) => s.id === dhcpSeg));
    $("#dhcp-form-ok").textContent = "Применено";
    await loadDhcp();
  } catch (e) { $("#dhcp-form-error").textContent = e.message; }
});

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
    renderStatic(await api("POST", `/api/dhcp/${dhcpSeg}/static-leases`,
      { mac: f.mac.value, ip: f.ip.value, name: f.name.value || null }));
    f.reset();
    await loadDhcp();
  } catch (e) { $("#static-error").textContent = e.message; }
});

$("#static-leases").addEventListener("click", async (ev) => {
  const b = ev.target.closest("button[data-unpin]");
  if (!b) return;
  $("#static-error").textContent = "";
  try {
    renderStatic(await api("DELETE", `/api/dhcp/${dhcpSeg}/static-leases/${encodeURIComponent(b.dataset.unpin)}`));
    await loadDhcp();
  } catch (e) { $("#static-error").textContent = e.message; }
});

// ---------------------------------------------------------------- DNS (BIND 9)
let dnsData = null;
let dnsZone = null;             // имя выбранной зоны; "new" — новая
let dnsFormLoaded = false;
let zoneFormFor = null;
const DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "NS", "CAA"];
const SOURCE = { dhcp: "DHCP", "static-lease": "закреплённый адрес", router: "роутер", ptr: "PTR по A-записи" };

function recordRow(r = {}) {
  const types = DNS_TYPES.map((t) => `<option ${t === (r.type || "A") ? "selected" : ""}>${t}</option>`).join("");
  return `<tr data-row="rec"><td>${inp("name", r.name, 'size="12" placeholder="www"')}</td>
    <td><select name="type">${types}</select></td>
    <td>${inp("value", r.value, 'size="22" placeholder="192.168.88.20"')}</td>
    <td>${inp("priority", r.priority, 'type="number" min="0" class="narrow"')}</td>
    <td>${inp("weight", r.weight, 'type="number" min="0" class="narrow"')}</td>
    <td>${inp("port", r.port, 'type="number" min="0" max="65535" class="narrow"')}</td>
    <td>${inp("ttl", r.ttl, 'type="number" min="0" class="narrow"')}</td>
    <td>${inp("comment", r.comment, 'size="14"')}</td>
    <td><button type="button" class="danger" data-del-row>×</button></td></tr>`;
}

function fillDnsForm(c) {
  const f = $("#dns-form");
  f.forwarders.value = csv(c.forwarders);
  f.forward_only.checked = c.forward_only;
  f.dnssec.checked = c.dnssec;
  f.cache_mb.value = c.cache_mb;
  f.allow.value = csv(c.allow);
  dnsFormLoaded = true;
}

function fillZoneForm() {
  const f = $("#zone-form");
  const z = dnsData.config.zones.find((x) => x.name === dnsZone)
    || { name: "", ttl: 3600, dhcp_names: true, auto_ptr: true, records: [] };
  const isNew = dnsZone === "new";
  f.zone_name.value = z.name;
  f.zone_name.readOnly = !isNew;
  $("#zone-rev-label").hidden = !isNew;
  f.reverse_net.value = "";
  f.zone_ttl.value = z.ttl;
  f.dhcp_names.checked = z.dhcp_names;
  f.auto_ptr.checked = z.auto_ptr;
  const info = dnsData.zones.find((x) => x.name === dnsZone);
  const segs = info ? info.segments.map(segNameDns).join(", ") : "";
  $("#zone-hint").textContent = isNew ? "Новая зона: обычная (office.lan) или обратная — укажите сеть, имя построится само."
    : info?.reverse ? "Обратная зона: адрес → имя (PTR)."
    : segs ? I18N.t("Домен сегментов: {s}. Имена их устройств из DHCP попадают сюда.", { s: segs })
    : "Ни один сегмент LAN не использует этот домен.";
  $("#zone-records").innerHTML = z.records.map(recordRow).join("");
  $("#zone-delete").hidden = isNew;
  zoneFormFor = dnsZone;
}

const segNameDns = (id) => (dnsData.segments.find((s) => s.id === id)?.name) || id;

async function loadDns() {
  const d = await api("GET", "/api/dns");
  dnsData = d;
  const c = d.config;
  if (dnsZone !== "new" && !c.zones.some((z) => z.name === dnsZone)) dnsZone = c.zones[0]?.name ?? "new";
  $("#dn-state").innerHTML = !d.installed ? '<span class="flag-x">нет в образе</span>'
    : d.running ? '<span class="flag-r">работает</span>' : d.listen.length ? '<span class="flag-x">не запущен</span>' : "выключен";
  $("#dn-listen").textContent = d.listen.length ? csv(d.listen) : "DNS не включён ни на одном LAN";
  $("#dn-fwd").textContent = d.forwarders.length ? csv(d.forwarders) + (c.forwarders.length ? "" : " (авто)") : "корневые серверы";
  $("#dn-zcount").textContent = c.zones.length;
  $("#dn-error").textContent = d.error || "";
  $("#zone-tabs").innerHTML = d.zones.map((z) => `<a class="tab ${z.name === dnsZone ? "active" : ""}" data-zone="${esc(z.name)}">${esc(z.name)}</a>`).join("")
    + `<a class="tab ${dnsZone === "new" ? "active" : ""}" data-zone="new">+ Зона</a>`;
  const auto = d.auto_names.filter((a) => a.zone === dnsZone);
  $("#zone-auto").innerHTML = auto.map((a) => `<tr><td>${esc(a.name)}</td><td>${esc(a.type)}</td><td>${esc(a.value)}</td>
    <td>${esc(SOURCE[a.source] || a.source)}</td></tr>`).join("") || '<tr><td colspan="4" class="hint">нет</td></tr>';
  if (!dnsFormLoaded) fillDnsForm(c);
  if (zoneFormFor !== dnsZone) fillZoneForm();
}

$("#zone-tabs").addEventListener("click", (ev) => {
  const t = ev.target.closest(".tab");
  if (!t) return;
  dnsZone = t.dataset.zone; zoneFormFor = null;
  document.querySelectorAll(".zone-error, .zone-ok").forEach((x) => { x.textContent = ""; });
  loadDns().catch(console.error);
});

$("#zone-record-add").addEventListener("click", () => $("#zone-records").insertAdjacentHTML("beforeend", recordRow()));
$("#zone-records").addEventListener("click", (ev) => { const b = ev.target.closest("[data-del-row]"); if (b) b.closest("tr").remove(); });

async function saveDns(config, okBox, errBox) {
  errBox.textContent = ""; okBox.textContent = "";
  try {
    const d = await api("PUT", "/api/dns", config);
    dnsData = d;
    okBox.textContent = "Применено";
    return d;
  } catch (e) { errBox.textContent = e.message; return null; }
}

$("#dns-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const c = { ...dnsData.config, forwarders: items(f.forwarders.value), forward_only: f.forward_only.checked,
              dnssec: f.dnssec.checked, cache_mb: num(f.cache_mb.value) ?? 64, allow: items(f.allow.value) };
  if (await saveDns(c, f.querySelector(".dns-form-ok"), f.querySelector(".dns-form-error"))) {
    fillDnsForm(dnsData.config);
    loadDns().catch(console.error);
  }
});

function reverseName(net) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(8|16|24)$/.exec(net.trim());
  if (!m) return null;
  const oct = [m[1], m[2], m[3]].slice(0, Number(m[5]) / 8);
  return oct.reverse().join(".") + ".in-addr.arpa";
}

$("#zone-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const err = f.querySelector(".zone-error"), ok = f.querySelector(".zone-ok");
  let name = f.zone_name.value.trim().toLowerCase().replace(/\.$/, "");
  if (dnsZone === "new" && f.reverse_net.value.trim()) {
    name = reverseName(f.reverse_net.value);
    if (!name) { err.textContent = I18N.t("обратная зона строится для сети /8, /16 или /24"); return; }
  }
  const val = (r, k) => r.querySelector(`[name=${k}]`).value;
  if (!name) { err.textContent = I18N.t("укажите имя зоны или сеть для обратной зоны"); return; }
  const zone = { name, ttl: num(f.zone_ttl.value) ?? 3600, dhcp_names: f.dhcp_names.checked, auto_ptr: f.auto_ptr.checked,
    records: [...$("#zone-records").querySelectorAll("[data-row]")].map((r) => ({
      name: val(r, "name").trim(), type: val(r, "type"), value: val(r, "value").trim(),
      priority: num(val(r, "priority")), weight: num(val(r, "weight")), port: num(val(r, "port")),
      ttl: num(val(r, "ttl")), comment: opt(val(r, "comment")),
    })).filter((r) => r.name && r.value) };
  const zones = dnsZone === "new" ? [...dnsData.config.zones, zone]
    : dnsData.config.zones.map((z) => (z.name === dnsZone ? zone : z));
  if (await saveDns({ ...dnsData.config, zones }, ok, err)) {
    dnsZone = name; zoneFormFor = null;
    loadDns().catch(console.error);
  }
});

$("#zone-delete").addEventListener("click", async () => {
  if (!confirm(I18N.t("Удалить зону {name} со всеми записями?", { name: dnsZone }))) return;
  const f = $("#zone-form");
  const zones = dnsData.config.zones.filter((z) => z.name !== dnsZone);
  if (await saveDns({ ...dnsData.config, zones }, f.querySelector(".zone-ok"), f.querySelector(".zone-error"))) {
    dnsZone = null; zoneFormFor = null;
    loadDns().catch(console.error);
  }
});

// ---------------------------------------------------------------- Files (Samba)
let fsTab = "overview";
let fsData = null;
let fsFormLoaded = false;
let shareEdit = null;           // имя редактируемой папки; "" — новая
const gb = (n) => (n == null ? "—" : n >= 1e12 ? `${(n / 1e12).toFixed(1)} TB` : n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : `${Math.round(n / 1e6)} MB`);

function selectFsTab(tab) {
  fsTab = tab;
  document.querySelectorAll("#files-tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === tab));
  for (const t of ["overview", "shares", "users", "disks"]) $(`#fs-${t}`).hidden = t !== tab;
  loadFiles().catch(console.error);
}
$("#files-tabs").addEventListener("click", (ev) => { const t = ev.target.closest(".tab"); if (t) selectFsTab(t.dataset.tab); });

async function putFiles(config, errBox) {
  if (errBox) errBox.textContent = "";
  try {
    fsData = await api("PUT", "/api/files", config);
    renderFiles();
    return true;
  } catch (e) { if (errBox) errBox.textContent = e.message; return false; }
}

function fillFilesForm() {
  const f = $("#files-form"), c = fsData.config;
  f.enabled.checked = c.enabled;
  f.workgroup.value = c.workgroup;
  f.netbios_name.value = c.netbios_name ?? "";
  f.server_string.value = c.server_string;
  f.min_protocol.value = c.min_protocol;
  f.netbios.checked = c.netbios;
  $("#fs-segments").innerHTML = fsData.segments.map((s) => `<label class="check"><input type="checkbox" name="segment" value="${esc(s.id)}"
    ${c.segments.includes(s.id) ? "checked" : ""}> ${esc(s.name)} (${esc(s.address)})</label>`).join("");
  fsFormLoaded = true;
}

function accessLabel(list) {
  return list.length ? list.map((x) => esc(x.startsWith("@") ? x : x)).join(", ") : "—";
}
const GUEST = { none: "нет", read: "чтение", write: "чтение и запись" };

function renderFiles() {
  const d = fsData, c = d.config;
  $("#fs-state").innerHTML = !d.installed ? '<span class="flag-x">нет в образе</span>'
    : d.running ? '<span class="flag-r">работает</span>' : c.enabled ? '<span class="flag-x">не запущена</span>' : "выключена";
  $("#fs-name").textContent = d.netbios_name;
  $("#fs-listen").textContent = d.listen.length ? csv(d.listen) : "—";
  $("#fs-sess-count").textContent = d.sessions.length;
  $("#fs-error").textContent = d.error || "";
  const ip = d.listen[0];
  $("#fs-howto").textContent = ip ? I18N.t("Windows: \\\\{ip} или \\\\{name} · macOS: smb://{ip} · Linux: smb://{ip}", { ip, name: d.netbios_name }) : "";
  $("#fs-volumes").innerHTML = d.volumes.map((v) => `<tr><td>${esc(v.name)}</td><td class="mono">${esc(v.path)}</td>
    <td>${gb(v.size)}</td><td>${gb(v.free)}</td><td>${v.mounted ? '<span class="flag-r">подключён</span>' : '<span class="flag-x">не подключён</span>'}</td></tr>`).join("");
  $("#fs-sessions").innerHTML = d.sessions.map((s) => `<tr><td>${esc(s.user)}</td><td>${esc(s.machine)}</td><td>${esc(s.protocol ?? "—")}</td>
    <td>${esc(s.share ?? "—")}</td><td>${s.open_files}</td></tr>`).join("") || '<tr><td colspan="5" class="hint">никого</td></tr>';

  $("#fs-share-list").innerHTML = c.shares.map((s) => `<tr class="${s.enabled ? "" : "row-disabled"}">
    <td>${esc(s.name)}</td><td class="mono">${esc(s.volume)}:/${esc(s.folder)}</td>
    <td>${accessLabel(s.read_users)}</td><td>${accessLabel(s.write_users)}</td><td>${GUEST[s.guest]}</td>
    <td>${s.recycle ? "да" : "—"}</td>
    <td class="actions"><button type="button" data-share-edit="${esc(s.name)}">Изменить</button>
      <button type="button" class="danger" data-share-del="${esc(s.name)}">Удалить</button></td></tr>`).join("")
    || '<tr><td colspan="7" class="hint">общих папок пока нет</td></tr>';

  const nopw = new Set(d.users_without_password);
  $("#fs-user-list").innerHTML = c.users.map((u) => `<tr class="${u.enabled ? "" : "row-disabled"}">
    <td>${esc(u.name)}</td><td>${esc(u.full_name ?? "—")}</td><td>${u.groups.map(esc).join(", ") || "—"}</td>
    <td>${nopw.has(u.name) ? '<span class="flag-x">не задан</span>' : "задан"}</td>
    <td>${u.enabled ? "включён" : "выключен"}</td>
    <td class="actions"><button type="button" data-user-pw="${esc(u.name)}">Сменить пароль</button>
      <button type="button" data-user-toggle="${esc(u.name)}">${u.enabled ? "Выключить" : "Включить"}</button>
      <button type="button" class="danger" data-user-del="${esc(u.name)}">Удалить</button></td></tr>`).join("")
    || '<tr><td colspan="6" class="hint">пользователей пока нет</td></tr>';
  $("#user-groups").innerHTML = c.groups.map((g) => `<label class="check"><input type="checkbox" name="ugroup" value="${esc(g.name)}"> ${esc(g.name)}</label>`).join("")
    || '<span class="hint">групп пока нет</span>';
  $("#fs-group-list").innerHTML = c.groups.map((g) => `<tr><td>${esc(g.name)}</td><td>${esc(g.description ?? "—")}</td>
    <td>${c.users.filter((u) => u.groups.includes(g.name)).map((u) => esc(u.name)).join(", ") || "—"}</td>
    <td class="actions"><button type="button" class="danger" data-group-del="${esc(g.name)}">Удалить</button></td></tr>`).join("")
    || '<tr><td colspan="4" class="hint">групп пока нет</td></tr>';

  $("#fs-disks-hint").textContent = d.disks_allowed
    ? "Подключите диск к серверу (USB, SATA), обновите страницу и нажмите «Подключить» у нужного раздела. Диск, на котором стоит сам сервер, недоступен."
    : "Управление дисками работает, когда роутер установлен на сервер (режим host). В режиме разработки и в GNS3 общие папки лежат во встроенном томе data.";
  $("#fs-dev-list").innerHTML = d.devices.map((x) => {
    const state = x.system ? '<span class="flag-x">системный</span>' : x.mounted_as ? `<span class="flag-r">${esc(x.mounted_as)}</span>` : "—";
    let act = "";
    if (!x.system && x.type === "part" && x.uuid && !x.mounted_as) act += `<button type="button" data-mount="${esc(x.uuid)}" data-dev="${esc(x.path)}" data-label="${esc(x.label ?? "")}">Подключить</button> `;
    if (x.mounted_as) act += `<button type="button" data-unmount="${esc(x.mounted_as)}">Отключить</button> `;
    if (!x.system && !x.mounted_as) act += `<button type="button" class="danger" data-format="${esc(x.path)}">Форматировать</button>`;
    return `<tr><td class="mono">${x.type === "part" ? "&nbsp;&nbsp;└ " : ""}${esc(x.path)}</td><td>${esc(x.model ?? (x.transport ? x.transport.toUpperCase() : "—"))}</td>
      <td>${gb(x.size)}${x.free != null ? ` · ${I18N.t("свободно {f}", { f: gb(x.free) })}` : ""}</td><td>${esc(x.fstype ?? "—")}</td><td>${esc(x.label ?? "—")}</td>
      <td>${state}</td><td class="actions">${act}</td></tr>`;
  }).join("") || `<tr><td colspan="7" class="hint">${d.disks_allowed ? "дисков не найдено" : "недоступно в этом режиме"}</td></tr>`;
}

async function loadFiles() {
  fsData = await api("GET", "/api/files");
  if (!fsFormLoaded) fillFilesForm();
  renderFiles();
}

$("#files-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const c = { ...fsData.config, enabled: f.enabled.checked, workgroup: f.workgroup.value.trim(),
    netbios_name: opt(f.netbios_name.value), server_string: f.server_string.value.trim(), min_protocol: f.min_protocol.value,
    netbios: f.netbios.checked, segments: [...f.querySelectorAll("input[name=segment]:checked")].map((i) => i.value) };
  f.querySelector(".fs-form-ok").textContent = "";
  if (await putFiles(c, f.querySelector(".fs-form-error"))) { f.querySelector(".fs-form-ok").textContent = "Применено"; fillFilesForm(); }
});

// --- общие папки ---
function openShareForm(name) {
  shareEdit = name;
  const c = fsData.config;
  const s = c.shares.find((x) => x.name === name)
    || { name: "", volume: "data", folder: "", comment: "", enabled: true, browseable: true, guest: "none",
         read_users: [], write_users: [], recycle: true, macos: false, hide_dot_files: true };
  const f = $("#share-form");
  $("#share-form-title").textContent = name ? I18N.t("Папка {name}", { name }) : I18N.t("Новая папка");
  f.enabled.checked = s.enabled; f.share_name.value = s.name; f.folder.value = s.folder; f.comment.value = s.comment ?? "";
  f.browseable.checked = s.browseable; f.guest.value = s.guest; f.recycle.checked = s.recycle; f.macos.checked = s.macos;
  f.hide_dot_files.checked = s.hide_dot_files;
  f.volume.innerHTML = fsData.volumes.map((v) => `<option value="${esc(v.name)}" ${v.name === s.volume ? "selected" : ""}>${esc(v.name)}</option>`).join("");
  const who = [...c.groups.map((g) => "@" + g.name), ...c.users.map((u) => u.name)];
  $("#share-access").innerHTML = who.map((w, i) => {
    const lvl = s.write_users.includes(w) ? "write" : s.read_users.includes(w) ? "read" : "none";
    return `<tr><td>${w.startsWith("@") ? `<b>${esc(w)}</b>` : esc(w)}</td>` + ["none", "read", "write"].map((l) =>
      `<td><input type="radio" name="acc${i}" value="${l}" data-who="${esc(w)}" ${l === lvl ? "checked" : ""}></td>`).join("") + "</tr>";
  }).join("") || '<tr><td colspan="4" class="hint">сначала создайте пользователей или включите гостей</td></tr>';
  f.querySelector(".share-error").textContent = "";
  f.hidden = false;
  f.scrollIntoView({ behavior: "smooth" });
}

$("#share-new").addEventListener("click", () => openShareForm(""));
$("#share-cancel").addEventListener("click", () => { $("#share-form").hidden = true; shareEdit = null; });
$("#fs-share-list").addEventListener("click", async (ev) => {
  const e = ev.target.closest("[data-share-edit]");
  if (e) { openShareForm(e.dataset.shareEdit); return; }
  const d = ev.target.closest("[data-share-del]");
  if (d && confirm(I18N.t("Удалить общую папку {name}? Файлы на диске останутся.", { name: d.dataset.shareDel }))) {
    await putFiles({ ...fsData.config, shares: fsData.config.shares.filter((s) => s.name !== d.dataset.shareDel) },
                   $("#share-form").querySelector(".share-error"));
  }
});

$("#share-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const radios = [...f.querySelectorAll("#share-access input[type=radio]:checked")];
  const share = { name: f.share_name.value.trim(), volume: f.volume.value, folder: f.folder.value.trim() || f.share_name.value.trim().toLowerCase(),
    comment: opt(f.comment.value), enabled: f.enabled.checked, browseable: f.browseable.checked, guest: f.guest.value,
    read_users: radios.filter((r) => r.value === "read").map((r) => r.dataset.who),
    write_users: radios.filter((r) => r.value === "write").map((r) => r.dataset.who),
    recycle: f.recycle.checked, macos: f.macos.checked, hide_dot_files: f.hide_dot_files.checked };
  const shares = shareEdit ? fsData.config.shares.map((s) => (s.name === shareEdit ? share : s)) : [...fsData.config.shares, share];
  if (await putFiles({ ...fsData.config, shares }, f.querySelector(".share-error"))) { f.hidden = true; shareEdit = null; }
});

// --- пользователи и группы ---
function withoutRefs(c, who) {
  const strip = (l) => l.filter((x) => x !== who);
  return c.shares.map((s) => ({ ...s, read_users: strip(s.read_users), write_users: strip(s.write_users) }))
    .filter((s) => s.guest !== "none" || s.read_users.length || s.write_users.length);
}

$("#user-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target, err = f.querySelector(".user-error");
  err.textContent = "";
  try {
    fsData = await api("POST", "/api/files/users", { name: f.login.value.trim(), full_name: opt(f.full_name.value),
      password: f.password.value, groups: [...f.querySelectorAll("input[name=ugroup]:checked")].map((i) => i.value) });
    f.reset();
    renderFiles();
  } catch (e) { err.textContent = e.message; }
});

$("#fs-user-list").addEventListener("click", async (ev) => {
  const err = $("#fs-users .fs-user-error");
  err.textContent = "";
  const pw = ev.target.closest("[data-user-pw]");
  if (pw) {
    const p = prompt(I18N.t("Новый пароль для {user} (не короче 6 символов):", { user: pw.dataset.userPw }));
    if (!p) return;
    try { fsData = await api("PUT", `/api/files/users/${encodeURIComponent(pw.dataset.userPw)}/password`, { password: p }); renderFiles(); }
    catch (e) { err.textContent = e.message; }
    return;
  }
  const t = ev.target.closest("[data-user-toggle]");
  if (t) {
    const users = fsData.config.users.map((u) => (u.name === t.dataset.userToggle ? { ...u, enabled: !u.enabled } : u));
    await putFiles({ ...fsData.config, users }, err);
    return;
  }
  const d = ev.target.closest("[data-user-del]");
  if (d && confirm(I18N.t("Удалить пользователя {name}? Его права на папки тоже будут убраны.", { name: d.dataset.userDel }))) {
    const c = fsData.config;
    await putFiles({ ...c, users: c.users.filter((u) => u.name !== d.dataset.userDel), shares: withoutRefs(c, d.dataset.userDel) }, err);
  }
});

$("#group-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const g = { name: f.group.value.trim(), description: opt(f.description.value) };
  if (await putFiles({ ...fsData.config, groups: [...fsData.config.groups, g] }, f.querySelector(".group-error"))) f.reset();
});

$("#fs-group-list").addEventListener("click", async (ev) => {
  const d = ev.target.closest("[data-group-del]");
  if (!d || !confirm(I18N.t("Удалить группу {name}?", { name: d.dataset.groupDel }))) return;
  const c = fsData.config, name = d.dataset.groupDel;
  await putFiles({ ...c, groups: c.groups.filter((g) => g.name !== name),
    users: c.users.map((u) => ({ ...u, groups: u.groups.filter((x) => x !== name) })), shares: withoutRefs(c, "@" + name) },
  $("#group-form").querySelector(".group-error"));
});

// --- диски ---
$("#fs-dev-list").addEventListener("click", async (ev) => {
  const err = $("#fs-disks .fs-disk-error");
  err.textContent = "";
  const m = ev.target.closest("[data-mount]");
  if (m) {
    const f = $("#mount-form");
    f.uuid.value = m.dataset.mount;
    f.volume_name.value = (m.dataset.label || "disk").toLowerCase().replace(/[^a-z0-9_-]/g, "") || "disk";
    $("#mount-what").textContent = m.dataset.dev;
    f.hidden = false;
    f.scrollIntoView({ behavior: "smooth" });
    return;
  }
  const u = ev.target.closest("[data-unmount]");
  if (u) {
    if (!confirm(I18N.t("Отключить диск {name}?", { name: u.dataset.unmount }))) return;
    try { fsData = await api("DELETE", `/api/files/disks/${encodeURIComponent(u.dataset.unmount)}`); renderFiles(); }
    catch (e) { err.textContent = e.message; }
    return;
  }
  const fm = ev.target.closest("[data-format]");
  if (fm) {
    const dev = fm.dataset.format;
    const answer = prompt(I18N.t("ВСЕ ДАННЫЕ на {dev} будут стёрты, будет создан раздел ext4. Для подтверждения введите имя устройства:", { dev }));
    if (answer === null) return;
    try { fsData = await api("POST", "/api/files/disks/format", { device: dev, label: "data", confirm: answer.trim() }); renderFiles(); }
    catch (e) { err.textContent = e.message; }
  }
});

$("#mount-cancel").addEventListener("click", () => { $("#mount-form").hidden = true; });
$("#mount-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target, err = f.querySelector(".mount-error");
  err.textContent = "";
  try {
    fsData = await api("POST", "/api/files/disks/mount", { uuid: f.uuid.value, name: f.volume_name.value.trim(),
      automount: f.automount.checked, read_only: f.read_only.checked });
    f.hidden = true;
    renderFiles();
  } catch (e) { err.textContent = e.message; }
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
  const isWol = name === "wol";
  $("#wol-panel").hidden = !isWol;
  for (const sel of ["#tool-form", ".tool-result"]) document.querySelector(`#page-tools ${sel}`).hidden = isWol;
  if (isWol) {
    $("#tool-summary").hidden = true;
    document.querySelectorAll("#tool-tabs .tab").forEach((x) => x.classList.toggle("active", x.dataset.tool === name));
    tool = name;
    return loadWolDevices();
  }
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

async function loadWolDevices() {
  const d = await api("GET", "/api/dhcp");
  const sel = $("#wol-lan"), cur = sel.value;
  sel.innerHTML = `<option value="">${esc(I18N.t("где устройство получало адрес"))}</option>`
    + d.segments.filter((s) => s.enabled).map((s) => `<option value="${esc(s.id)}">${esc(s.name)}</option>`).join("");
  sel.value = cur;
  const segName = Object.fromEntries(d.segments.map((s) => [s.id, s.name]));
  const seen = new Set();
  const rows = [];
  for (const s of d.segments) for (const x of s.static_leases ?? []) {
    seen.add(x.mac); rows.push({ name: x.name, ip: x.ip, mac: x.mac, lan: s.id });
  }
  for (const x of d.leases) if (!seen.has(x.mac)) rows.push({ name: x.name ?? x.hostname, ip: x.ip, mac: x.mac, lan: x.lan });
  $("#wol-devices").innerHTML = rows.map((x) => `<tr><td>${dash(x.name)}</td><td>${esc(x.ip)}</td><td>${esc(x.mac)}</td>
    <td>${esc(segName[x.lan] ?? x.lan)}</td><td class="actions"><button type="button" data-wol="${esc(x.mac)}" data-lan="${esc(x.lan)}">Разбудить</button></td></tr>`).join("")
    || '<tr><td colspan="5" class="hint">нет устройств в DHCP</td></tr>';
}
$("#wol-devices").addEventListener("click", (ev) => {
  const b = ev.target.closest("button[data-wol]");
  if (b) wakeUp(b.dataset.wol, b.dataset.lan, $("#wol-ok"), $("#wol-error"));
});
$("#wol-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  wakeUp(ev.target.mac.value.trim(), ev.target.lan.value, $("#wol-ok"), $("#wol-error"));
});

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
  } else if (sysTab === "ntp") {
    const n = await api("GET", "/api/system/ntp");
    const c = n.config;
    $("#ntp-time").textContent = n.time ? new Date(n.time).toLocaleString(I18N.locale()) : "—";
    $("#ntp-sync").innerHTML = !c.enabled ? "выключено" : !n.installed ? '<span class="flag-x">нет в образе</span>'
      : n.synced ? '<span class="flag-r">синхронизировано</span>' : n.running ? "синхронизируется…" : '<span class="flag-x">не запущен</span>';
    $("#ntp-ref").textContent = n.reference ?? "—";
    $("#ntp-offset").textContent = n.offset == null ? "—" : I18N.t("{v} мс", { v: (n.offset * 1000).toFixed(3) });
    $("#ntp-stratum").textContent = n.stratum ?? "—";
    $("#ntp-serving").textContent = n.serving.join(", ") || "нет";
    $("#ntp-error").textContent = n.error ?? "";
    $("#ntp-clock").textContent = c.enabled ? (n.clock_control ? "Роутер сам подводит часы системы."
      : "Режим Docker: часы общие с хостом — их подводит сам хост; роутер следит за точностью и раздаёт время в LAN.") : "";
    $("#ntp-sources").innerHTML = n.sources.map((x) => `<tr><td><b>${esc(x.state)}</b></td><td>${esc(x.address)}</td>
      <td class="num">${dash(x.stratum)}</td><td class="num">${x.reach == null ? "—" : [...x.reach.toString(2)].filter((b) => b === "1").length}</td>
      <td class="num">${x.offset == null ? "—" : esc(I18N.t("{v} мс", { v: (x.offset * 1000).toFixed(3) }))}</td></tr>`).join("")
      || `<tr><td colspan="5" class="hint">${c.enabled ? "источников пока нет" : "NTP выключен"}</td></tr>`;
    if (!ntpFormLoaded) {
      const f = $("#ntp-form");
      $("#ntp-tz").innerHTML = `<option value="">${esc(I18N.t("как у системы ({tz})", { tz: n.timezone }))}</option>`
        + n.timezones.map((z) => `<option ${z === c.timezone ? "selected" : ""}>${esc(z)}</option>`).join("");
      f.enabled.checked = c.enabled; f.servers.value = c.servers.join(", ");
      f.serve_lan.checked = c.serve_lan; f.orphan.checked = c.orphan;
      ntpFormLoaded = true;
    }
  } else if (sysTab === "audit") {
    const log = await api("GET", "/api/system/audit?limit=300");
    $("#audit").innerHTML = log.map((x) => `
      <tr class="${x.status >= 400 ? "row-inactive" : ""}"><td>${new Date(x.time).toLocaleString(I18N.locale())}</td><td>${esc(x.user)}</td>
        <td>${esc(x.method)}</td><td class="mono">${esc(x.path)}</td><td>${x.status}</td><td>${esc(x.ip)}</td></tr>`).join("")
      || '<tr><td colspan="6" class="hint">записей нет</td></tr>';
  }
}

let ntpFormLoaded = false;
$("#ntp-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("#ntp-ok").textContent = ""; $("#ntp-form-error").textContent = "";
  try {
    await api("PUT", "/api/system/ntp", { enabled: f.enabled.checked, servers: f.servers.value.split(/[\s,;]+/).filter(Boolean),
      serve_lan: f.serve_lan.checked, orphan: f.orphan.checked, timezone: f.timezone.value || null });
    ntpFormLoaded = false;
    $("#ntp-ok").textContent = "Применено";
    await loadSystemPage();
  } catch (e) { $("#ntp-form-error").textContent = e.message; }
});

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

// ---------------------------------------------------------------- Monitoring
let monTab = "overview";
let monRange = "1h";
let monSnap = null;
let monHist = null;              // { ключ: { start, step, values } }
let monHistAt = 0;
let monHistKey = "";
let monIf = null;                // интерфейс, выбранный во вкладке «Интерфейсы»
let monSettings = null;
let monFormLoaded = false;
const MON_HIST_EVERY = { "1h": 10e3, "24h": 60e3, "7d": 300e3, "30d": 600e3 };
const MON_COLORS = ["--series-1", "--series-2", "--series-3", "--series-4", "--series-5", "--series-6"];
const monColor = (i) => `var(${MON_COLORS[i % MON_COLORS.length]})`;

const bits = (b) => {
  if (b == null) return "—";
  const u = ["bps", "kbps", "Mbps", "Gbps"]; let i = 0;
  while (Math.abs(b) >= 1000 && i < u.length - 1) { b /= 1000; i++; }
  return `${i === 0 || b >= 100 ? Math.round(b) : +b.toFixed(1)} ${u[i]}`;
};
const bps = (bytesPerSec) => (bytesPerSec == null ? "—" : bits(bytesPerSec * 8));
const pct = (v) => (v == null ? "—" : v === 0 ? "0%" : `${v < 10 ? v.toFixed(1) : Math.round(v)}%`);
const monMs = (v) => (v == null ? "—" : `${v === 0 ? 0 : v < 10 ? v.toFixed(1) : Math.round(v)} мс`);
const pingName = (p) => (p.name === "gateway" ? I18N.t("шлюз {ip}", { ip: p.target })
  : p.name === "gateway2" ? I18N.t("шлюз WAN2 {ip}", { ip: p.target }) : p.target);

// --- график: линии с заливкой, сетка, подписи осей, перекрестие и подсказка при наведении
function niceMax(v) {
  if (!(v > 0)) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const f = v / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p;
}

function timeLabel(t, step, full) {
  const d = new Date(t * 1000);
  const p2 = (n) => String(n).padStart(2, "0");
  const hm = `${p2(d.getHours())}:${p2(d.getMinutes())}`;
  const dm = `${p2(d.getDate())}.${p2(d.getMonth() + 1)}`;
  if (full) return step >= 600 || monRange !== "1h" ? `${dm} ${hm}` : `${hm}:${p2(d.getSeconds())}`;
  return step >= 600 ? dm : hm;
}

function drawChart(el, opt) {
  // opt: { series: [{ name, color, values }], start, step, fmt, max, empty }
  el._chart = opt;
  const series = opt.series.filter((s) => s.values);
  const n = Math.max(0, ...series.map((s) => s.values.length));
  const legend = series.length > 1
    ? series.map((s) => `<span><i class="swatch" style="background:${s.color}"></i>${esc(s.name)}</span>`).join("") : "";
  el.innerHTML = `<div class="chart-legend">${legend}</div><div class="plot"></div>`;
  const plot = el.querySelector(".plot");
  const vals = series.flatMap((s) => s.values).filter((v) => v != null);
  if (!vals.length || n < 2) {
    plot.innerHTML = `<div class="empty">${esc(opt.empty || "Нет данных за этот период")}</div>`;
    return;
  }
  const W = plot.clientWidth || 520, H = plot.clientHeight || 190;
  const m = { l: 64, r: 12, t: 8, b: 22 };
  const top = opt.max ?? niceMax(Math.max(...vals) * 1.05 / 4) * 4;   // четыре ровных шага сетки
  const X = (i) => m.l + (W - m.l - m.r) * i / (n - 1);
  const Y = (v) => m.t + (H - m.t - m.b) * (1 - Math.min(v, top) / top);
  let svg = "";
  for (let k = 0; k <= 4; k++) {                  // сетка и подписи оси Y
    const v = top * k / 4, y = Y(v).toFixed(1);
    svg += `<line x1="${m.l}" x2="${W - m.r}" y1="${y}" y2="${y}" style="stroke:var(${k ? "--grid" : "--axis"})" stroke-width="1"/>`;
    svg += `<text x="${m.l - 8}" y="${(+y + 4).toFixed(1)}" text-anchor="end">${esc(opt.fmt(v))}</text>`;
  }
  const ticks = Math.min(6, Math.max(2, Math.floor((W - m.l - m.r) / 110)));
  for (let k = 0; k <= ticks; k++) {              // подписи оси X
    const i = Math.round((n - 1) * k / ticks);
    const anchor = k === 0 ? "start" : k === ticks ? "end" : "middle";
    svg += `<text x="${X(i).toFixed(1)}" y="${H - 6}" text-anchor="${anchor}">${timeLabel(opt.start + i * opt.step, opt.step)}</text>`;
  }
  series.forEach((s) => {                         // заливка и линия, разрывы там, где данных нет
    let line = "", area = "", seg = [];
    const flush = () => {
      if (!seg.length) return;
      line += seg.map(([x, y], j) => `${j ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join("");
      area += `M${seg[0][0].toFixed(1)} ${Y(0).toFixed(1)}` + seg.map(([x, y]) => `L${x.toFixed(1)} ${y.toFixed(1)}`).join("")
        + `L${seg[seg.length - 1][0].toFixed(1)} ${Y(0).toFixed(1)}Z`;
      seg = [];
    };
    s.values.forEach((v, i) => (v == null ? flush() : seg.push([X(i), Y(v)])));
    flush();
    svg += `<path d="${area}" style="fill:${s.color}" fill-opacity="0.08"/>`;
    svg += `<path d="${line}" fill="none" style="stroke:${s.color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
  });
  svg += `<line class="xh" y1="${m.t}" y2="${H - m.b}" style="stroke:var(--text-muted)" stroke-width="1" stroke-dasharray="3 3" visibility="hidden"/>`;
  svg += series.map((s, k) => `<circle class="pt" data-k="${k}" r="4" style="fill:${s.color};stroke:var(--surface-1)" stroke-width="2" visibility="hidden"/>`).join("");
  svg += `<rect x="${m.l}" y="0" width="${W - m.l - m.r}" height="${H}" fill="transparent" class="hit"/>`;
  plot.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img">${svg}</svg><div class="chart-tip" hidden></div>`;

  const svgEl = plot.querySelector("svg"), tip = plot.querySelector(".chart-tip"), xh = plot.querySelector(".xh");
  const pts = [...plot.querySelectorAll(".pt")];
  const hide = () => { tip.hidden = true; xh.setAttribute("visibility", "hidden"); pts.forEach((p) => p.setAttribute("visibility", "hidden")); };
  plot.querySelector(".hit").addEventListener("mouseleave", hide);
  plot.querySelector(".hit").addEventListener("mousemove", (ev) => {
    const r = svgEl.getBoundingClientRect();
    const px = (ev.clientX - r.left) * W / r.width;
    const i = Math.max(0, Math.min(n - 1, Math.round((px - m.l) / (W - m.l - m.r) * (n - 1))));
    const x = X(i);
    xh.setAttribute("x1", x); xh.setAttribute("x2", x); xh.setAttribute("visibility", "visible");
    let rows = "";
    series.forEach((s, k) => {
      const v = s.values[i];
      if (v == null) { pts[k].setAttribute("visibility", "hidden"); }
      else { pts[k].setAttribute("cx", x); pts[k].setAttribute("cy", Y(v)); pts[k].setAttribute("visibility", "visible"); }
      rows += `<div class="row"><i class="swatch" style="background:${s.color}"></i>${esc(s.name)}<b>${v == null ? "—" : esc(opt.fmt(v))}</b></div>`;
    });
    tip.innerHTML = `<div class="time">${timeLabel(opt.start + i * opt.step, opt.step, true)}</div>${rows}`;
    tip.hidden = false;
    const left = x * r.width / W;
    tip.style.top = "4px";
    tip.style.left = `${Math.min(Math.max(0, left + 12), r.width - tip.offsetWidth)}px`;
    if (left + 12 + tip.offsetWidth > r.width) tip.style.left = `${Math.max(0, left - 12 - tip.offsetWidth)}px`;
  });
}

let monResizeTimer = null;
window.addEventListener("resize", () => {
  clearTimeout(monResizeTimer);
  monResizeTimer = setTimeout(() => document.querySelectorAll("#page-monitor .chart").forEach((el) => {
    if (el._chart && el.offsetParent) drawChart(el, el._chart);
  }), 150);
});

const hseries = (key, scale = 1) => {
  const s = monHist?.[key];
  return s ? s.values.map((v) => (v == null ? null : v * scale)) : null;
};
const hmeta = () => Object.values(monHist ?? {})[0] ?? { start: 0, step: 10 };

// --- вкладки и период
function selectMonTab(tab) {
  monTab = tab;
  document.querySelectorAll("#mon-tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === tab));
  for (const t of ["overview", "interfaces", "clients", "export"]) $(`#mon-${t}`).hidden = t !== tab;
  $("#mon-range").hidden = !(tab === "overview" || tab === "interfaces");
  monHistKey = "";
  if (location.hash === "#monitor") loadMonitor().catch(console.error);
}
$("#mon-tabs").addEventListener("click", (ev) => { const t = ev.target.closest(".tab"); if (t) selectMonTab(t.dataset.tab); });
$("#mon-range").addEventListener("click", (ev) => {
  const b = ev.target.closest("button[data-range]");
  if (!b) return;
  monRange = b.dataset.range;
  document.querySelectorAll("#mon-range button").forEach((x) => x.classList.toggle("active", x === b));
  monHistKey = "";
  loadMonitor().catch(console.error);
});

async function loadMonitor() {
  monSnap = await api("GET", "/api/monitor");
  if (monTab === "overview") renderMonTiles();
  if (monTab === "interfaces") renderMonIfaces();
  if (monTab === "clients") renderMonClients();
  if (monTab === "export") await loadMonSettings();
  if (monTab === "overview" || monTab === "interfaces") await loadMonHistory();
}

function monChartIfaces() {
  return (monSnap?.interfaces ?? []).filter((i) => i.role === "lan" || i.role === "vpn");
}

function monKeys() {
  if (monTab === "interfaces") return monIf ? [`if:${monIf}:rx`, `if:${monIf}:tx`] : [];
  const keys = ["cpu", "mem"];
  const wan = monSnap?.wan?.interface;
  if (wan) keys.push(`if:${wan}:rx`, `if:${wan}:tx`);
  for (const p of monSnap?.ping ?? []) keys.push(`ping:${p.name}:rtt`, `ping:${p.name}:loss`);
  for (const i of monChartIfaces()) keys.push(`if:${i.name}:rx`, `if:${i.name}:tx`);
  return keys;
}

async function loadMonHistory() {
  const keys = monKeys();
  const sig = `${monTab}|${monRange}|${keys.join(",")}`;
  if (sig === monHistKey && Date.now() - monHistAt < MON_HIST_EVERY[monRange]) return;
  if (!keys.length) { monHist = {}; monHistKey = sig; renderMonCharts(); return; }
  const r = await api("GET", `/api/monitor/history?range=${monRange}&keys=${encodeURIComponent(keys.join(","))}`);
  monHist = r.series; monHistKey = sig; monHistAt = Date.now();
  renderMonCharts();
}

function trafficChart(el, name, down, up, downName, upName) {
  const { start, step } = hmeta();
  drawChart(el, { start, step, fmt: bits, series: [
    { name: downName, color: monColor(0), values: hseries(`if:${name}:${down}`, 8) },
    { name: upName, color: monColor(1), values: hseries(`if:${name}:${up}`, 8) }] });
}

function renderMonCharts() {
  const { start, step } = hmeta();
  if (monTab === "interfaces") {
    if (monIf) trafficChart($("#ch-if"), monIf, "rx", "tx", "↓ Приём", "↑ Передача");
    return;
  }
  const wan = monSnap?.wan?.interface;
  if (wan) trafficChart($("#ch-wan"), wan, "rx", "tx", "↓ Загрузка", "↑ Отдача");
  else drawChart($("#ch-wan"), { series: [], start, step, fmt: bits, empty: "WAN не настроен" });
  const pings = monSnap?.ping ?? [];
  drawChart($("#ch-rtt"), { start, step, fmt: monMs, empty: "Нет данных — проверьте адреса во вкладке «Экспорт»",
    series: pings.map((p, k) => ({ name: pingName(p), color: monColor(k), values: hseries(`ping:${p.name}:rtt`) })) });
  drawChart($("#ch-loss"), { start, step, fmt: pct, max: 100,
    series: pings.map((p, k) => ({ name: pingName(p), color: monColor(k), values: hseries(`ping:${p.name}:loss`) })) });
  drawChart($("#ch-sys"), { start, step, fmt: pct, max: 100, series: [
    { name: "CPU", color: monColor(0), values: hseries("cpu") },
    { name: "Память", color: monColor(1), values: hseries("mem") }] });

  const box = $("#mon-seg-charts");
  const ifs = monChartIfaces();
  const want = ifs.map((i) => i.name).join(",");
  if (box.dataset.ifs !== want) {
    box.dataset.ifs = want;
    box.innerHTML = ifs.map((i) => `<div class="card chart-card"><h2>${esc(i.label || i.name)} · ${esc(i.name)}</h2>`
      + `<div class="chart" data-if="${esc(i.name)}"></div></div>`).join("")
      || `<p class="hint">Нет активных сегментов LAN и туннелей VPN.</p>`;
  }
  for (const i of ifs) {
    const el = box.querySelector(`.chart[data-if="${CSS.escape(i.name)}"]`);
    if (i.role === "vpn") trafficChart(el, i.name, "rx", "tx", "↓ Из туннеля", "↑ В туннель");
    else trafficChart(el, i.name, "tx", "rx", "↓ К клиентам", "↑ От клиентов");
  }
}

function mtile(label, value, sub, meter, small) {
  return `<div class="mtile"><div class="label">${label}</div><div class="value${small ? " small" : ""}">${value}</div>`
    + `<div class="sub">${sub ?? ""}</div>`
    + (meter != null ? `<div class="meter"><i style="width:${Math.max(0, Math.min(100, meter))}%"></i></div>` : "")
    + "</div>";
}
const stateDot = (ok, text) => `<span class="state"><span class="dot ${ok ? "ok" : "bad"}"></span>${text}</span>`;

function renderMonTiles() {
  const s = monSnap;
  if (!s?.time) {
    $("#mon-tiles").innerHTML = `<p class="hint">Сбор данных начался — первые значения появятся через 10–20 секунд.</p>`;
    return;
  }
  const y = s.system, mem = y.memory ?? {}, disk = (y.disks ?? [])[0];
  const gw = (s.ping ?? []).find((p) => p.name === "gateway");
  const leases = (s.dhcp ?? []).reduce((a, d) => a + d.leases, 0);
  const t = [
    ...(s.wans?.length ? s.wans.map((w) => mtile(w.name, stateDot(w.healthy !== false, w.healthy === false ? "нет связи" : "работает"),
      esc(w.interface ?? "") + (w.active ? " · " + I18N.t("трафик") : ""), null, true))
      : [mtile("WAN", stateDot(s.wan.up, s.wan.up ? "работает" : "нет связи"), esc([s.wan.interface, s.wan.gateway].filter(Boolean).join(" → ")), null, true)]),
    mtile("CPU", pct(y.cpu), y.load ? `load ${y.load.map((x) => x.toFixed(2)).join(" ")}` : "", y.cpu),
    mtile("Память", pct(mem.percent), `${fmt(mem.used ?? 0)} / ${fmt(mem.total ?? 0)}`, mem.percent),
    disk ? mtile("Диск", pct(disk.percent), `${fmt(disk.used)} / ${fmt(disk.total)}`, disk.percent) : "",
    mtile("Задержка до шлюза", monMs(gw?.rtt), gw ? I18N.t("потери {p}", { p: pct(gw.loss) }) : "нет шлюза"),
    mtile("Клиенты DHCP", String(leases), (s.dhcp ?? []).map((d) => `${esc(d.name)}: ${d.leases}`).join(" · ")),
    mtile("Время работы", duration(y.uptime), "", null, true),
    y.temperature != null ? mtile("Температура", `${y.temperature} °C`, "") : "",
    s.vpn ? mtile("VPN", stateDot(s.vpn.up, s.vpn.up ? "подключён" : "нет связи"), esc(s.vpn.kind), null, true) : "",
    s.routing?.bgp?.length ? mtile("BGP", `${s.routing.bgp.filter((p) => p.up).length} / ${s.routing.bgp.length}`, "сессий установлено") : "",
    s.smb_sessions != null ? mtile("Samba", String(s.smb_sessions), "подключений") : "",
  ];
  $("#mon-tiles").innerHTML = t.join("");
}

const roleBadge = (r) => (r ? `<span class="badge ${r}">${{ wan: "WAN", lan: "LAN", vpn: "VPN", vlan: "VLAN", port: "порт" }[r] ?? r}</span>` : "—");

function renderMonIfaces() {
  const ifs = monSnap?.interfaces ?? [];
  if (!monIf || !ifs.some((i) => i.name === monIf)) {
    monIf = (ifs.find((i) => i.role === "wan") ?? ifs[0])?.name ?? null;
  }
  $("#mon-if-table").innerHTML = ifs.map((i) => `<tr data-if="${esc(i.name)}" class="${i.name === monIf ? "selected" : ""}">
    <td><b>${esc(i.name)}</b></td><td>${roleBadge(i.role)}</td><td>${dash(i.label)}</td>
    <td>${i.up ? '<span class="dot ok"></span>' : '<span class="dot bad"></span>'}</td>
    <td class="num">${i.speed ? bits(i.speed) : "—"}</td>
    <td class="num">${bps(i.rx_rate)}</td><td class="num">${bps(i.tx_rate)}</td>
    <td class="num">${fmt(i.rx_bytes)}</td><td class="num">${fmt(i.tx_bytes)}</td>
    <td class="num">${i.rx_errors + i.tx_errors}</td><td class="num">${i.rx_dropped + i.tx_dropped}</td></tr>`).join("")
    || `<tr><td colspan="11">—</td></tr>`;
  const cur = ifs.find((i) => i.name === monIf);
  $("#mon-if-title").textContent = cur ? `${cur.name}${cur.label ? " · " + cur.label : ""}` : "—";
}
$("#mon-if-table").addEventListener("click", (ev) => {
  const tr = ev.target.closest("tr[data-if]");
  if (!tr) return;
  monIf = tr.dataset.if;
  renderMonIfaces();
  loadMonHistory().catch(console.error);
});

function renderMonClients() {
  const s = monSnap ?? {};
  $("#mon-cl-error").textContent = s.time && !s.accounting
    ? I18N.t("Учёт трафика клиентов недоступен: {e}", { e: s.accounting_error || "нет активных сегментов LAN" }) : "";
  const sel = $("#mon-cl-seg");
  const segs = [...new Set((s.clients ?? []).map((c) => c.segment).filter(Boolean))].sort();
  const want = segs.join("|");
  if (sel.dataset.segs !== want) {
    const cur = sel.value;
    sel.dataset.segs = want;
    sel.innerHTML = `<option value="">все</option>` + segs.map((x) => `<option>${esc(x)}</option>`).join("");
    sel.value = segs.includes(cur) ? cur : "";
  }
  const q = $("#mon-cl-filter").value.trim().toLowerCase();
  const rows = (s.clients ?? [])
    .filter((c) => !sel.value || c.segment === sel.value)
    .filter((c) => !q || [c.name, c.ip, c.mac].some((x) => (x ?? "").toLowerCase().includes(q)))
    .sort((a, b) => ((b.rx_rate ?? 0) + (b.tx_rate ?? 0)) - ((a.rx_rate ?? 0) + (a.tx_rate ?? 0))
      || (b.rx_bytes + b.tx_bytes) - (a.rx_bytes + a.tx_bytes));
  $("#mon-cl-count").textContent = I18N.t("устройств: {n}", { n: rows.length });
  $("#mon-cl-table").innerHTML = rows.map((c) => `<tr><td>${dash(c.name)}</td><td>${esc(c.ip)}</td><td>${dash(c.mac)}</td>
    <td>${dash(c.segment)}</td><td class="num">${bps(c.rx_rate)}</td><td class="num">${bps(c.tx_rate)}</td>
    <td class="num">${fmt(c.rx_bytes)}</td><td class="num">${fmt(c.tx_bytes)}</td></tr>`).join("")
    || `<tr><td colspan="8">${s.time ? "Пока нет трафика через роутер" : "Сбор данных начался…"}</td></tr>`;
}
$("#mon-cl-seg").addEventListener("change", renderMonClients);
$("#mon-cl-filter").addEventListener("input", renderMonClients);

// --- экспорт: Prometheus, SNMP, Zabbix agent
const listOf = (v) => v.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);

function expState(el, st) {
  if (!st.enabled) { el.innerHTML = ""; return; }
  if (!st.installed) { el.innerHTML = `<span class="dot bad"></span><span class="error">не установлен в образе — пересоберите образ</span>`; return; }
  el.innerHTML = st.running
    ? `<span class="dot ok"></span>${esc(I18N.t("работает"))}${st.flavor ? ` <span class="legend">(${esc(st.flavor)})</span>` : ""}`
    : `<span class="dot bad"></span><span class="error">${esc(st.error || "не запущен")}</span>`;
}

function snmpVersionChanged() {
  const v3 = $("#mon-form").snmp_version.value === "v3";
  $("#mon-snmp-v2").hidden = v3;
  $("#mon-snmp-v3").hidden = !v3;
}
$("#mon-form").snmp_version.addEventListener("change", snmpVersionChanged);

function fillMonForm() {
  const f = $("#mon-form"), c = monSettings.config;
  f.ping_targets.value = c.ping_targets.join(", ");
  f.prom_enabled.checked = c.prometheus.enabled;
  f.prom_token.value = c.prometheus.token ?? "";
  f.prom_allowed.value = c.prometheus.allowed.join(", ");
  const s = c.snmp;
  f.snmp_enabled.checked = s.enabled;
  f.snmp_version.value = s.version;
  f.snmp_community.value = s.community;
  f.snmp_user.value = s.user ?? "";
  f.snmp_auth.value = ""; f.snmp_priv.value = "";
  f.snmp_location.value = s.location ?? "";
  f.snmp_contact.value = s.contact ?? "";
  f.snmp_allowed.value = s.allowed.join(", ");
  const z = c.zabbix;
  f.zbx_enabled.checked = z.enabled;
  f.zbx_server.value = z.server.join(", ");
  f.zbx_active.value = z.server_active ?? "";
  f.zbx_hostname.value = z.hostname ?? "";
  f.zbx_metadata.value = z.metadata ?? "";
  snmpVersionChanged();
}

async function loadMonSettings() {
  monSettings = await api("GET", "/api/monitor/settings");
  if (!monFormLoaded) { fillMonForm(); monFormLoaded = true; }
  expState($("#mon-snmp-state"), monSettings.snmp);
  expState($("#mon-zbx-state"), monSettings.zabbix);
  $("#mon-prom-url").textContent = `${location.protocol}//${location.host}/metrics`;
  $("#mon-lan-access").textContent = I18N.t("Из сегментов LAN доступ к экспорту открыт всегда: {nets}. Для других адресов (через WAN, VPN, из сети Docker) заполните поля «Откуда ещё» — роутер откроет порт в фаерволе только для них.",
    { nets: monSettings.lan_networks.join(", ") || "—" });
}

$("#mon-token-gen").addEventListener("click", () => {
  const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const r = crypto.getRandomValues(new Uint8Array(32));
  $("#mon-form").prom_token.value = [...r].map((x) => abc[x % abc.length]).join("");
});

$("#mon-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("#mon-ok").textContent = ""; $("#mon-error").textContent = "";
  const body = {
    ping_targets: listOf(f.ping_targets.value),
    prometheus: { enabled: f.prom_enabled.checked, token: f.prom_token.value.trim() || null, allowed: listOf(f.prom_allowed.value) },
    snmp: { enabled: f.snmp_enabled.checked, version: f.snmp_version.value, community: f.snmp_community.value.trim(),
            user: f.snmp_user.value.trim() || null, auth_password: f.snmp_auth.value || null, priv_password: f.snmp_priv.value || null,
            location: f.snmp_location.value.trim() || null, contact: f.snmp_contact.value.trim() || null,
            allowed: listOf(f.snmp_allowed.value) },
    zabbix: { enabled: f.zbx_enabled.checked, server: listOf(f.zbx_server.value), server_active: f.zbx_active.value.trim() || null,
              hostname: f.zbx_hostname.value.trim() || null, metadata: f.zbx_metadata.value.trim() || null },
  };
  try {
    monSettings = await api("PUT", "/api/monitor/settings", body);
    fillMonForm();
    expState($("#mon-snmp-state"), monSettings.snmp);
    expState($("#mon-zbx-state"), monSettings.zabbix);
    $("#mon-ok").textContent = "Применено";
  } catch (e) { $("#mon-error").textContent = e.message; }
});

// ---------------------------------------------------------------- QoS
let qosData = null;
let qosFormLoaded = false;
let qosDhcp = [];

function qosDeviceRow(d = {}) {
  return `<tr data-row><td><input type="checkbox" name="enabled" ${d.enabled === false ? "" : "checked"}></td>
    <td><input name="name" value="${esc(d.name ?? "")}" size="16"></td>
    <td><input name="ip" value="${esc(d.ip ?? "")}" size="15" placeholder="192.168.88.20"></td>
    <td><input name="down" type="number" min="0.1" step="0.1" class="narrow" value="${d.down ?? ""}"></td>
    <td><input name="up" type="number" min="0.1" step="0.1" class="narrow" value="${d.up ?? ""}"></td>
    <td><button type="button" class="danger" data-del-row>✕</button></td></tr>`;
}

function fillQosForm() {
  const f = $("#qos-form"), c = qosData.config;
  f.qos_enabled.checked = c.enabled; f.voice.checked = c.voice;
  f.wan_down.value = c.wan_down ?? ""; f.wan_up.value = c.wan_up ?? "";
  f.sip_ports.value = c.sip_ports; f.rtp_ports.value = c.rtp_ports;
  const lim = Object.fromEntries(c.segments.map((x) => [x.lan, x]));
  $("#qos-segments").innerHTML = qosData.segments.map((s) => `<tr data-seg="${esc(s.id)}"><td>${esc(s.name)}</td><td>${esc(s.network)}</td>
    <td><input name="down" type="number" min="0.1" step="0.1" class="narrow" value="${lim[s.id]?.down ?? ""}"></td>
    <td><input name="up" type="number" min="0.1" step="0.1" class="narrow" value="${lim[s.id]?.up ?? ""}"></td></tr>`).join("")
    || '<tr><td colspan="4" class="hint">нет включённых сегментов LAN</td></tr>';
  $("#qos-devices").innerHTML = c.devices.map(qosDeviceRow).join("");
}

async function loadQos() {
  qosData = await api("GET", "/api/qos");
  const c = qosData.config;
  $("#qos-state").innerHTML = !c.enabled ? "выключены" : qosData.active ? '<span class="flag-r">работают</span>'
    : '<span class="flag-x">не применились</span>';
  $("#qos-error").textContent = qosData.error ?? "";
  $("#qos-stats").innerHTML = qosData.stats.map((x) => `<tr><td>${esc(x.label)}</td><td>${esc(x.dev)}</td>
    <td class="num">${fmt(x.bytes)}</td><td class="num">${x.packets}</td><td class="num">${x.drops}</td></tr>`).join("")
    || `<tr><td colspan="5" class="hint">${c.enabled ? "нет данных" : "QoS выключен"}</td></tr>`;
  if (!qosFormLoaded) {
    fillQosForm(); qosFormLoaded = true;
    try {
      const d = await api("GET", "/api/dhcp");
      const seen = new Set();
      qosDhcp = [];
      for (const s of d.segments) for (const x of s.static_leases ?? []) { seen.add(x.ip); qosDhcp.push({ ip: x.ip, name: x.name }); }
      for (const x of d.leases) if (!seen.has(x.ip)) qosDhcp.push({ ip: x.ip, name: x.name ?? x.hostname });
      $("#qos-from-dhcp").innerHTML = `<option value="">${esc(I18N.t("+ из списка DHCP…"))}</option>`
        + qosDhcp.map((x, i) => `<option value="${i}">${esc(x.name ?? "—")} · ${esc(x.ip)}</option>`).join("");
    } catch (e) { console.error(e); }
  }
}

$("#qos-add").addEventListener("click", () => $("#qos-devices").insertAdjacentHTML("beforeend", qosDeviceRow()));
$("#qos-from-dhcp").addEventListener("change", (ev) => {
  const x = qosDhcp[Number(ev.target.value)];
  if (x) $("#qos-devices").insertAdjacentHTML("beforeend", qosDeviceRow({ ip: x.ip, name: x.name }));
  ev.target.value = "";
});
$("#qos-devices").addEventListener("click", (ev) => { const b = ev.target.closest("[data-del-row]"); if (b) b.closest("tr").remove(); });

$("#qos-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("#qos-ok").textContent = ""; $("#qos-form-error").textContent = "";
  const body = {
    enabled: f.qos_enabled.checked, voice: f.voice.checked, wan_down: num(f.wan_down.value), wan_up: num(f.wan_up.value),
    sip_ports: f.sip_ports.value, rtp_ports: f.rtp_ports.value,
    segments: [...$("#qos-segments").querySelectorAll("tr[data-seg]")].map((r) => ({
      lan: r.dataset.seg, down: num(r.querySelector("[name=down]").value), up: num(r.querySelector("[name=up]").value) }))
      .filter((x) => x.down || x.up),
    devices: [...$("#qos-devices").querySelectorAll("tr[data-row]")].map((r) => ({
      enabled: r.querySelector("[name=enabled]").checked, name: opt(r.querySelector("[name=name]").value),
      ip: r.querySelector("[name=ip]").value.trim(), down: num(r.querySelector("[name=down]").value),
      up: num(r.querySelector("[name=up]").value) })).filter((x) => x.ip),
  };
  try {
    qosData = await api("PUT", "/api/qos", body);
    fillQosForm();
    $("#qos-ok").textContent = "Применено";
    await loadQos();
  } catch (e) { $("#qos-form-error").textContent = e.message; }
});

// ---------------------------------------------------------------- Scheduler
let schData = null;
let schEdit = null;          // id редактируемой задачи; null — новая
const SCH_DAYS = ["пн", "вт", "ср", "чт", "пт", "сб", "вс"];
$("#sch-days").innerHTML = SCH_DAYS.map((d, i) => `<label><input type="checkbox" value="${i}" ${i < 5 ? "checked" : ""}> ${d}</label>`).join("");

function schKindChanged() {
  const f = $("#sch-form"), k = f.kind.value, a = f.type.value;
  f.querySelectorAll("[data-k]").forEach((el) => { el.hidden = !el.dataset.k.split(" ").includes(k); });
  f.querySelectorAll("[data-a]").forEach((el) => { el.hidden = !el.dataset.a.split(" ").includes(a); });
}
$("#sch-form").addEventListener("change", (ev) => {
  if (["kind", "type"].includes(ev.target.name)) schKindChanged();
  if (ev.target.name === "device_pick" && ev.target.value) $("#sch-form").mac.value = ev.target.value;
});

function schFillSelects() {
  const t = schData.targets, f = $("#sch-form");
  const opts = (list, val, label) => list.map((x) => `<option value="${esc(val(x))}">${esc(label(x))}</option>`).join("");
  $("#sch-type").innerHTML = opts(Object.entries(schData.actions), (x) => x[0], (x) => x[1]);
  $("#sch-wol-pick").innerHTML = `<option value="">${esc(I18N.t("— ввести MAC вручную —"))}</option>`
    + opts(t.devices, (x) => x.mac, (x) => `${x.name ?? x.ip} · ${x.mac}`);
  $("#sch-lan").innerHTML = opts(t.segments, (x) => x.name, (x) => x.name);
  $("#sch-rule").innerHTML = opts(t.rules, (x) => x.id, (x) => `#${x.id} ${x.name}`) || `<option value="">${esc(I18N.t("нет правил"))}</option>`;
  $("#sch-forward").innerHTML = opts(t.forwards, (x) => x.id, (x) => `#${x.id} ${x.name}`) || `<option value="">${esc(I18N.t("нет пробросов"))}</option>`;
  $("#sch-qdev").innerHTML = opts(t.qos_devices, (x) => x.ip, (x) => `${x.name ?? ""} ${x.ip}`) || `<option value="">${esc(I18N.t("нет ограничений устройств"))}</option>`;
  f.dataset.ready = "1";
}

function schResetForm(task) {
  const f = $("#sch-form");
  schEdit = task?.id ?? null;
  $("#sch-form-title").textContent = task ? I18N.t("Задача: {n}", { n: task.name }) : "Новая задача";
  $("#sch-form-error").textContent = "";
  const s = task?.schedule ?? { kind: "daily", time: "08:00", days: [0, 1, 2, 3, 4], every: 60 };
  const a = task?.action ?? { type: "wol", enabled: true, wan: "wan1" };
  f.name.value = task?.name ?? ""; f.enabled.checked = task ? task.enabled : true;
  f.kind.value = s.kind; f.time.value = s.time ?? "08:00"; f.every.value = s.every ?? 60;
  f.at.value = s.at ?? ""; f.cron.value = s.cron ?? "";
  $("#sch-days").querySelectorAll("input").forEach((c) => { c.checked = (s.days ?? []).includes(Number(c.value)); });
  f.type.value = a.type; f.mac.value = a.mac ?? ""; f.device_pick.value = "";
  if (a.lan) f.lan.value = a.lan;
  if (a.type === "firewall_rule" && a.target != null) f.rule.value = a.target;
  if (a.type === "port_forward" && a.target != null) f.forward.value = a.target;
  if (a.device) f.qdev.value = a.device;
  f.onoff.value = a.enabled === false ? "0" : "1"; f.wan.value = a.wan ?? "wan1";
  schKindChanged();
}

async function loadScheduler() {
  schData = await api("GET", "/api/scheduler");
  if (!$("#sch-form").dataset.ready) { schFillSelects(); schResetForm(null); }
  $("#sch-clock").textContent = I18N.t("Часовой пояс роутера: {tz} · сейчас {now} (изменить — System → Время)",
    { tz: schData.timezone, now: new Date(schData.now).toLocaleString(I18N.locale()) });
  const when = (x) => (x ? new Date(x).toLocaleString(I18N.locale()) : "—");
  $("#sch-tasks").innerHTML = schData.tasks.map((t) => `<tr class="${t.enabled ? "" : "row-disabled"}">
    <td><b>${esc(t.name)}</b></td><td data-no-i18n>${esc(schDescribe(t))}</td><td>${t.enabled ? when(t.next_run) : esc(I18N.t("выключена"))}</td>
    <td>${t.last_run ? `${t.last_ok ? '<span class="dot ok"></span>' : '<span class="dot bad"></span>'} ${when(t.last_run)}` : "—"}</td>
    <td class="actions"><button type="button" data-run="${t.id}">Выполнить</button>
      <button type="button" data-edit="${t.id}">Изменить</button>
      <button type="button" data-toggle="${t.id}">${t.enabled ? "Выключить" : "Включить"}</button>
      <button type="button" data-del="${t.id}" class="danger">Удалить</button></td></tr>`).join("")
    || '<tr><td colspan="5" class="hint">задач пока нет — добавьте первую ниже</td></tr>';
  $("#sch-log").innerHTML = schData.log.map((r) => `<tr class="${r.ok ? "" : "row-inactive"}"><td>${when(r.time)}</td>
    <td>${esc(r.name)}${r.manual ? ` <span class="hint">(${esc(I18N.t("вручную"))})</span>` : ""}</td><td>${esc(r.message)}</td></tr>`).join("")
    || '<tr><td colspan="3" class="hint">запусков пока не было</td></tr>';
}

const schTask = (id) => schData.tasks.find((t) => t.id === Number(id));

// описание задачи — из частей, каждая переводится словарём
function schDescribe(t) {
  const s = t.schedule, a = t.action, tr = (x, v) => I18N.t(x, v);
  const days = (s.days ?? []).map((d) => tr(SCH_DAYS[d])).join(", ");
  const when = s.kind === "daily" ? tr("каждый день в {t}", { t: s.time })
    : s.kind === "weekly" ? tr("{d} в {t}", { d: days, t: s.time })
    : s.kind === "interval" ? tr("каждые {n} мин", { n: s.every })
    : s.kind === "once" ? tr("один раз {at}", { at: (s.at ?? "").replace("T", " ") })
    : `cron ${s.cron}`;
  const on = a.enabled !== false;
  const what = {
    wol: () => tr("разбудить {m}", { m: a.mac }),
    lan_segment: () => tr(on ? "включить сегмент {s}" : "выключить сегмент {s}", { s: a.lan }),
    firewall_rule: () => tr(on ? "включить правило #{n}" : "выключить правило #{n}", { n: a.target }),
    port_forward: () => tr(on ? "включить проброс #{n}" : "выключить проброс #{n}", { n: a.target }),
    vpn: () => tr(on ? "включить VPN" : "выключить VPN"),
    qos_device: () => tr(on ? "включить ограничение {ip}" : "выключить ограничение {ip}", { ip: a.device }),
    backup: () => tr("резервная копия конфигурации"),
    wan_renew: () => tr("обновить аренду {w}", { w: a.wan.toUpperCase() }),
    multiwan_primary: () => tr("основной канал — {w}", { w: a.wan.toUpperCase() }),
    restart: () => tr("перезапуск сервиса"),
  }[a.type]?.() ?? a.type;
  return `${when} → ${what}`;
}
const schBody = (t) => ({ name: t.name, enabled: t.enabled, schedule: t.schedule, action: t.action });

$("#sch-tasks").addEventListener("click", async (ev) => {
  const b = ev.target.closest("button");
  if (!b) return;
  $("#sch-msg").textContent = ""; $("#sch-error").textContent = "";
  try {
    if (b.dataset.run) {
      const r = await api("POST", `/api/scheduler/tasks/${b.dataset.run}/run`);
      (r.ok ? $("#sch-msg") : $("#sch-error")).textContent = r.message;
    } else if (b.dataset.edit) {
      schResetForm(schTask(b.dataset.edit));
      $("#sch-form").scrollIntoView({ behavior: "smooth" });
      return;
    } else if (b.dataset.toggle) {
      const t = schTask(b.dataset.toggle);
      await api("PUT", `/api/scheduler/tasks/${t.id}`, { ...schBody(t), enabled: !t.enabled });
    } else if (b.dataset.del) {
      if (!confirm(I18N.t("Удалить задачу «{n}»?", { n: schTask(b.dataset.del).name }))) return;
      await api("DELETE", `/api/scheduler/tasks/${b.dataset.del}`);
      if (schEdit === Number(b.dataset.del)) schResetForm(null);
    }
    await loadScheduler();
  } catch (e) { $("#sch-error").textContent = e.message; }
});

$("#sch-cancel").addEventListener("click", () => schResetForm(null));

$("#sch-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  $("#sch-form-error").textContent = "";
  const kind = f.kind.value, type = f.type.value;
  const schedule = { kind };
  if (kind === "daily" || kind === "weekly") schedule.time = f.time.value;
  if (kind === "weekly") schedule.days = [...$("#sch-days").querySelectorAll("input:checked")].map((c) => Number(c.value));
  if (kind === "interval") schedule.every = Number(f.every.value);
  if (kind === "once") schedule.at = f.at.value;
  if (kind === "cron") schedule.cron = f.cron.value;
  const action = { type, enabled: f.onoff.value === "1", wan: f.wan.value };
  if (type === "wol") action.mac = f.mac.value.trim();
  if (type === "lan_segment") action.lan = f.lan.value;
  if (type === "firewall_rule") action.target = num(f.rule.value);
  if (type === "port_forward") action.target = num(f.forward.value);
  if (type === "qos_device") action.device = f.qdev.value;
  const body = { name: f.name.value, enabled: f.enabled.checked, schedule, action };
  try {
    if (schEdit) await api("PUT", `/api/scheduler/tasks/${schEdit}`, body);
    else await api("POST", "/api/scheduler/tasks", body);
    schResetForm(null);
    $("#sch-msg").textContent = "Сохранено";
    await loadScheduler();
  } catch (e) { $("#sch-form-error").textContent = e.message; }
});

// ---------------------------------------------------------------- экспорт командами
$("#export-secrets").addEventListener("change", (ev) => {
  $("#export-download").href = `/api/system/export?download=true${ev.target.checked ? "&show_sensitive=true" : ""}`;
});
$("#export-show").addEventListener("click", async () => {
  const r = await fetch(`/api/system/export${$("#export-secrets").checked ? "?show_sensitive=true" : ""}`);
  const pre = $("#export-text");
  pre.textContent = r.ok ? await r.text() : `${r.status} ${r.statusText}`;
  pre.hidden = false;
});

// ---------------------------------------------------------------- навигация
const pages = {
  "status": loadStatus,
  "monitor": loadMonitor,
  "wan": loadWan,
  "lan": loadLan,
  "dhcp": loadDhcp,
  "dns": loadDns,
  "files": loadFiles,
  "vpn": loadVpn,
  "firewall": loadFirewall,
  "routing": loadRouting,
  "qos": loadQos,
  "scheduler": loadScheduler,
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
  selectFsTab("overview");
  selectMonTab("overview");
  selectWanTab("wan1");
  document.querySelector('#mon-range button[data-range="1h"]').classList.add("active");
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
