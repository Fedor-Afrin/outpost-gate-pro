// OutpostGate Pro — переключение языка интерфейса на лету (RU / EN / HE).
//
// Как работает: исходный текст страницы и app.js — русский. После каждой отрисовки
// MutationObserver находит новые текстовые узлы (и атрибуты placeholder / title) и
// подменяет их по словарю i18n-dict.js. Оригинал хранится при узле, поэтому язык можно
// переключать сколько угодно раз, без перезагрузки и без правок в app.js.
// Для текстов вне страницы (confirm / prompt / alert) — I18N.t() и I18N.tr().
(function () {
  "use strict";
  const LANGS = { en: "English", ru: "Русский", he: "עברית" };
  const COL = { en: 0, he: 1 };
  const LOCALE = { ru: "ru-RU", en: "en-GB", he: "he-IL" };
  const SKIP = "script, style, textarea, pre, [data-no-i18n]";
  const ATTRS = ["placeholder", "title"];

  const norm = (s) => s.replace(/\s+/g, " ").trim();
  const exact = new Map();     // фраза -> [en, he]
  const patterns = [];         // { re, names, v }
  for (const [k, v] of Object.entries(window.I18N_DICT || {})) {
    const key = norm(k);
    exact.set(key, v);
    if (!/\{\w+\}/.test(key)) continue;
    const names = [];
    const src = key.split(/(\{\w+\})/).map((part) => {
      const m = /^\{(\w+)\}$/.exec(part);
      if (m) { names.push(m[1]); return "(.+?)"; }
      return part.replace(/[.*+?^$()|[\]\\{}]/g, "\\$&");
    }).join("");
    patterns.push({ re: new RegExp("^" + src + "$", "s"), names, v, len: key.length });
  }
  patterns.sort((a, b) => b.len - a.len);   // длинные (более точные) шаблоны — первыми

  let lang = "ru";
  const cache = new Map();

  const fill = (tpl, vars) => tpl.replace(/\{(\w+)\}/g, (m, n) => (n in vars ? vars[n] : m));

  // Перевести фразу целиком; null — перевода нет.
  function lookup(core, depth) {
    const col = COL[lang];
    const hit = exact.get(core);
    if (hit && !/\{\w+\}/.test(core)) return hit[col];
    if (depth > 3) return null;
    for (const p of patterns) {
      const m = p.re.exec(core);
      if (!m) continue;
      const vars = {};
      p.names.forEach((n, i) => { vars[n] = lookup(m[i + 1], depth + 1) ?? m[i + 1]; });
      return fill(p.v[col], vars);
    }
    if (core.includes(" · ")) {          // «весь трафик · kill switch» — по частям
      const parts = core.split(" · ");
      const out = parts.map((x) => lookup(x, depth + 1));
      if (out.some((x) => x != null)) return out.map((x, i) => x ?? parts[i]).join(" · ");
    }
    if (core.endsWith(":") && core.length > 1) {   // «Протокол:» и т.п.
      const x = lookup(core.slice(0, -1).trimEnd(), depth + 1);
      if (x != null) return x + ":";
    }
    return null;
  }

  // Текст (с пробелами по краям) -> перевод на текущий язык.
  function tr(s) {
    if (lang === "ru" || s == null) return s;
    s = String(s);
    const core = norm(s);
    if (!core || (!/[А-Яа-яЁё]/.test(core) && !exact.has(core))) return s;
    const key = lang + "\u0000" + core;
    let out = cache.get(key);
    if (out === undefined) {
      out = lookup(core, 0);
      if (cache.size > 5000) cache.clear();
      cache.set(key, out);
    }
    if (out == null) return s;
    const lead = /^\s*/.exec(s)[0], trail = /\s*$/.exec(s)[0];
    return lead + out + trail;
  }

  // Явный перевод с подстановкой: t("Удалить пользователя {name}?", { name })
  function t(src, vars = {}) {
    const v = exact.get(norm(src));
    const tpl = lang !== "ru" && v ? v[COL[lang]] : src;
    const tvars = {};
    for (const k in vars) tvars[k] = tr(vars[k]);
    return fill(tpl, tvars);
  }

  // ---------------------------------------------------------------- DOM
  const textOrig = new WeakMap();   // текстовый узел -> { src, last }
  const attrOrig = new WeakMap();   // элемент -> { attr: { src, last } }

  function skipped(el) { return !el || (el.closest && el.closest(SKIP)); }

  function doText(n) {
    const cur = n.nodeValue;
    let o = textOrig.get(n);
    if (!o) {
      if (lang === "ru" || !/[А-Яа-яЁёA-Za-z]/.test(cur) || skipped(n.parentElement)) return;
      o = { src: cur, last: cur }; textOrig.set(n, o);
    } else if (cur !== o.last) { o.src = cur; }         // текст поменял app.js
    const out = tr(o.src);
    o.last = out;
    if (out !== cur) n.nodeValue = out;
  }

  function doAttr(el, a) {
    const cur = el.getAttribute(a);
    if (cur == null) return;
    let m = attrOrig.get(el);
    if (!m) { m = {}; attrOrig.set(el, m); }
    let o = m[a];
    if (!o) { if (lang === "ru") return; o = m[a] = { src: cur, last: cur }; }
    else if (cur !== o.last) o.src = cur;
    const out = tr(o.src);
    o.last = out;
    if (out !== cur) el.setAttribute(a, out);
  }

  function walk(root) {
    if (root.nodeType === 3) { doText(root); return; }
    if (root.nodeType !== 1 && root.nodeType !== 9) return;
    if (root.nodeType === 1) {
      if (skipped(root)) return;
      ATTRS.forEach((a) => root.hasAttribute(a) && doAttr(root, a));
    }
    root.querySelectorAll("[placeholder], [title]").forEach((el) => {
      if (!skipped(el)) ATTRS.forEach((a) => el.hasAttribute(a) && doAttr(el, a));
    });
    const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    for (let n = w.nextNode(); n; n = w.nextNode()) doText(n);
  }

  const observer = new MutationObserver((list) => {
    for (const m of list) {
      if (m.type === "childList") m.addedNodes.forEach(walk);
      else if (m.type === "characterData") doText(m.target);
      else if (m.type === "attributes" && !skipped(m.target)) doAttr(m.target, m.attributeName);
    }
  });

  // ---------------------------------------------------------------- язык
  function initialLang() {
    try { const s = localStorage.getItem("og_lang"); if (s && LANGS[s]) return s; } catch (_) { /* нет storage */ }
    return "en";   // по умолчанию — английский; выбор пользователя запоминается в браузере
  }

  function markButtons() {
    document.querySelectorAll(".lang-switch [data-lang]").forEach((b) =>
      b.classList.toggle("active", b.dataset.lang === lang));
  }

  function setLang(l) {
    if (!LANGS[l]) return;
    lang = l;
    try { localStorage.setItem("og_lang", l); } catch (_) { /* приватный режим */ }
    document.documentElement.lang = l;
    document.documentElement.dir = l === "he" ? "rtl" : "ltr";
    walk(document.body);
    markButtons();
  }

  document.addEventListener("click", (e) => {
    const b = e.target.closest && e.target.closest(".lang-switch [data-lang]");
    if (b) { e.preventDefault(); setLang(b.dataset.lang); }
  });

  window.I18N = {
    LANGS, t, tr, setLang,
    lang: () => lang,
    locale: () => LOCALE[lang],
  };

  setLang(initialLang());
  observer.observe(document.body, {
    subtree: true, childList: true, characterData: true,
    attributes: true, attributeFilter: ATTRS,
  });
})();
