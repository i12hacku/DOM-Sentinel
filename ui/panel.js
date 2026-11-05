// Shared UI for the side panel and the DevTools panel.
// All page-derived data is rendered with textContent — never innerHTML — so a
// scanned page cannot inject markup into the extension UI.

const IS_DEVTOOLS = Boolean(chrome.devtools && chrome.devtools.inspectedWindow);
const SEVS = ["high", "medium", "low", "info"];
const $ = (id) => document.getElementById(id);

const state = {
  tabId: null,
  windowId: null,
  url: "",
  report: null,
  sevFilter: new Set(SEVS),
  logs: []
};

// ---------- tiny helpers ----------

function h(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) e.append(kid instanceof Node ? kid : String(kid));
  return e;
}

async function send(type, extra = {}) {
  if (state.tabId == null) throw new Error("No target tab.");
  const res = await chrome.runtime.sendMessage({ type, tabId: state.tabId, ...extra });
  if (!res) throw new Error("No response from the background worker — reload the extension.");
  if (!res.ok) throw new Error(res.error);
  return res.data;
}

function setStatus(msg, isError = false) {
  const s = $("status");
  s.textContent = msg || "";
  s.classList.toggle("err", isError);
}

async function busy(btn, fn) {
  btn.disabled = true;
  try { return await fn(); } catch (e) { setStatus(e.message, true); return undefined; } finally { btn.disabled = false; }
}

function devtoolsEval(expr) {
  return new Promise((resolve, reject) => {
    chrome.devtools.inspectedWindow.eval(expr, (result, exc) => {
      if (exc && (exc.isException || exc.isError)) reject(new Error(exc.value || exc.description || exc.code || "Evaluation failed"));
      else resolve(result);
    });
  });
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (_) {
    const ta = h("textarea", {}, text);
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  setStatus("Copied.");
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const sameDoc = (a, b) => String(a || "").split("#")[0] === String(b || "").split("#")[0];
const fmtBytes = (n) => (n > 1e6 ? (n / 1e6).toFixed(1) + " MB" : n > 1e3 ? Math.round(n / 1e3) + " KB" : n + " B");

// ---------- target tab ----------

async function resolveTarget() {
  if (IS_DEVTOOLS) {
    state.tabId = chrome.devtools.inspectedWindow.tabId;
    try { state.url = (await chrome.tabs.get(state.tabId)).url || ""; } catch (_) {
      try { state.url = await devtoolsEval("location.href"); } catch (_) { state.url = ""; }
    }
  } else {
    const [tab] = await chrome.tabs.query(state.windowId != null ? { active: true, windowId: state.windowId } : { active: true, currentWindow: true });
    state.tabId = tab?.id ?? null;
    state.url = tab?.url || "";
  }
  $("target").textContent = state.url || "No tab";
  $("target").title = state.url;
  await loadReport();
}

async function loadReport() {
  state.report = null;
  try {
    const r = await send("GET_REPORT");
    if (r && sameDoc(r.url, state.url)) state.report = r;
  } catch (_) { /* ignore */ }
  renderAll();
}

// ---------- scanning ----------

async function scan() {
  setStatus("Scanning…");
  const t = performance.now();
  const report = await send("SCAN", { options: { active: $("activeToggle").checked } });
  state.report = report;
  setStatus(`Done in ${((performance.now() - t) / 1000).toFixed(1)}s — ${report.findings.length} findings.`);
  renderAll();
}

function renderAll() {
  renderFindings();
  renderHidden();
  renderRecon();
  const c = state.report?.counts;
  $("badge").textContent = c ? String(c.high + c.medium || "") : "";
}

// ---------- findings ----------

function renderFindings() {
  const r = state.report;
  const summary = $("summary");
  summary.replaceChildren(...SEVS.map((s) => h("div", {
    class: `chip ${s}${state.sevFilter.has(s) ? "" : " off"}`,
    title: "Click to show/hide",
    onclick: () => { state.sevFilter.has(s) ? state.sevFilter.delete(s) : state.sevFilter.add(s); renderFindings(); }
  }, h("b", { text: String(r?.counts?.[s] ?? 0) }), s)));

  const list = $("findings");
  if (!r) {
    list.replaceChildren(h("p", { class: "empty" }, "Click ", h("b", { text: "Scan page" }), " to analyse the current tab. Scanning is local — nothing is sent anywhere unless you use the AI tab."));
    return;
  }
  const q = $("search").value.trim().toLowerCase();
  const shown = r.findings.filter((f) => state.sevFilter.has(f.severity) && (!q || `${f.title} ${f.category} ${f.description} ${f.evidence}`.toLowerCase().includes(q)));
  const groups = new Map();
  for (const f of shown) {
    if (!groups.has(f.category)) groups.set(f.category, []);
    groups.get(f.category).push(f);
  }
  const nodes = [];
  for (const [cat, items] of groups) {
    nodes.push(h("details", { class: "group", open: true },
      h("summary", { text: `${cat} (${items.length})` }),
      items.map(findingCard)));
  }
  list.replaceChildren(...(nodes.length ? nodes : [h("p", { class: "empty", text: "No findings match the current filter." })]));
}

function findingCard(f) {
  const card = h("div", { class: `finding ${f.severity}` });
  const actions = h("div", { class: "actions" });
  if (f.selector) {
    actions.append(h("button", { class: "small", text: "Highlight", onclick: () => highlight(f.selector) }));
    actions.append(h("button", { class: "small", text: "Inspector", onclick: () => openInInspector(f.selector) }));
    if (IS_DEVTOOLS) actions.append(h("button", { class: "small", text: "Show in Elements", onclick: () => showInElements(f.selector) }));
  }
  actions.append(h("button", { class: "small ghost", text: "Copy", onclick: () => copyText(findingText(f)) }));
  card.append(
    h("div", { class: "head", onclick: () => card.classList.toggle("open") },
      h("span", { class: `sev ${f.severity}`, text: f.severity }),
      h("span", { text: f.title })),
    h("div", { class: "body" },
      h("p", { text: f.description }),
      f.evidence ? h("pre", { text: f.evidence }) : null,
      f.recommendation ? h("p", { class: "fix", text: "→ " + f.recommendation }) : null,
      actions)
  );
  return card;
}

const findingText = (f) => `[${f.severity.toUpperCase()}] ${f.title}\nCategory: ${f.category}\n\n${f.description}\n\nEvidence:\n${f.evidence || "-"}\n\nRecommendation: ${f.recommendation || "-"}`;

async function highlight(selector, ref) {
  try {
    const r = await send("HIGHLIGHT", { selector, ref });
    setStatus(r?.hidden ? `Element is hidden (${r.hidden}) — use Reveal to see it.` : "Highlighted on page.");
  } catch (e) { setStatus(e.message, true); }
}

async function showInElements(selector) {
  try {
    const found = await devtoolsEval(`(() => { const e = document.querySelector(${JSON.stringify(selector)}); if (e) inspect(e); return !!e; })()`);
    setStatus(found ? "Selected in Elements panel." : "Element not found.", !found);
  } catch (e) { setStatus(e.message, true); }
}

function openInInspector(selector) {
  $("selector").value = selector;
  switchTab("inspector");
  readElement();
}

// ---------- hidden ----------

function renderHidden() {
  const r = state.report;
  const list = $("hiddenList");
  if (!r) { $("hiddenSummary").textContent = ""; list.replaceChildren(h("p", { class: "empty", text: "Scan first." })); return; }
  const only = $("onlyInteresting").checked;
  const items = (r.hidden || []).filter((x) => !only || x.interesting);
  const interesting = (r.hidden || []).filter((x) => x.interesting).length;
  $("hiddenSummary").textContent = `${r.hiddenTotal} hidden element tree(s) found, ${interesting} look interesting. Showing ${items.length}.`;
  list.replaceChildren(...items.map((x) => h("div", { class: "item" },
    h("div", {},
      h("span", { class: "tag" + (x.interesting ? " bad" : ""), text: x.interesting ? "interesting" : x.isWidget ? "ui widget" : "hidden" }),
      h("span", { class: "tag", text: x.reason }),
      h("code", { text: x.selector })),
    x.why.length ? h("div", { class: "meta", text: x.why.join(" · ") }) : null,
    x.text ? h("div", { class: "meta", text: "“" + x.text + "”" }) : null,
    h("details", {}, h("summary", { class: "meta", text: "HTML" }), h("pre", { class: "out", text: x.html })),
    h("div", { class: "actions" },
      h("button", { class: "small", text: "Reveal", onclick: () => reveal(true, false, x.ref) }),
      h("button", { class: "small", text: "Highlight", onclick: () => highlight(x.selector, x.ref) }),
      h("button", { class: "small ghost", text: "Inspector", onclick: () => openInInspector(x.selector) }),
      IS_DEVTOOLS ? h("button", { class: "small ghost", text: "Elements", onclick: () => showInElements(x.selector) }) : null)
  )));
  if (!items.length) list.append(h("p", { class: "empty", text: only ? "No interesting hidden elements. Untick the filter to see everything." : "No hidden elements found." }));
}

async function reveal(on, onlyInteresting, ref) {
  try {
    const r = await send("REVEAL_HIDDEN", { on, onlyInteresting, ref });
    if (on) setStatus(r.revealed ? `Revealed ${r.revealed} element(s) (pink dashed outline).` : "Nothing revealed — the page changed, rescan first.", !r.revealed);
    else setStatus(`Restored ${r.restored} element(s).`);
    if (on && typeof ref === "number") highlight(null, ref);
  } catch (e) { setStatus(e.message, true); }
}

// ---------- recon ----------

function section(title, count, ...content) {
  return h("details", { class: "group" }, h("summary", { text: `${title}${count != null ? ` (${count})` : ""}` }), ...content);
}

function kv(pairs) {
  return h("div", { class: "kv" }, pairs.flatMap(([k, v]) => [h("span", { text: k }), h("code", { text: v })]));
}

function renderRecon() {
  const r = state.report;
  const el = $("recon");
  if (!r) { el.replaceChildren(h("p", { class: "empty", text: "Scan first." })); return; }
  const parts = [];

  parts.push(kv([
    ["Scanned", new Date(r.scannedAt).toLocaleString() + ` (${(r.durationMs / 1000).toFixed(1)}s)`],
    ["Elements", String(r.stats?.elements)],
    ["Forms / scripts / iframes", `${r.stats?.forms} / ${r.stats?.scripts} / ${r.stats?.iframes}`],
    ["Console capture", r.consoleHook ? "active" : "inactive (reload the page)"],
    ["Active checks", r.activeChecks ? "yes" : "no"]
  ]));

  if (r.headers) parts.push(section("Response headers", r.headers.list.length,
    h("p", { class: "muted small", text: `HTTP ${r.headers.statusCode} via ${r.headers.via}` }),
    kv(r.headers.list.map((x) => [x.name, x.value]))));

  parts.push(section("Cookies", r.cookies.length, r.cookies.map((c) => h("div", { class: "item" },
    h("code", { text: c.name }), " ",
    h("span", { class: "tag " + (c.httpOnly ? "good" : "bad"), text: c.httpOnly ? "HttpOnly" : "JS-readable" }),
    h("span", { class: "tag " + (c.secure ? "good" : "bad"), text: c.secure ? "Secure" : "not Secure" }),
    h("span", { class: "tag", text: "SameSite=" + c.sameSite }),
    h("span", { class: "tag", text: c.session ? "session" : "persistent" }),
    h("div", { class: "meta", text: `${c.domain}${c.path} · ${c.size} chars` })))));

  parts.push(section("Libraries", r.libraries?.length || 0, (r.libraries || []).map((l) => h("div", { class: "item" }, h("b", { text: l.name }), " ", h("code", { text: l.version || "version unknown" }), h("span", { class: "meta", text: "  via " + l.how })))));

  const ep = r.endpoints || [];
  parts.push(section("Endpoints & URLs in code", ep.length,
    h("div", { class: "actions" }, h("button", { class: "small ghost", text: "Copy all", onclick: () => copyText(ep.map((e) => e.url).join("\n")) })),
    ep.map((e) => h("div", { class: "item" },
      e.interesting ? h("span", { class: "tag bad", text: "interesting" }) : null,
      e.external ? h("span", { class: "tag", text: "external" }) : null,
      h("code", { text: e.url }),
      h("div", { class: "meta", text: "in " + e.from })))));

  parts.push(section("Scripts", r.scripts?.length || 0, (r.scripts || []).map((s) => h("div", { class: "item" },
    h("span", { class: "tag", text: s.sameSite ? "first-party" : "third-party" }), h("code", { text: s.url }), h("span", { class: "meta", text: "  " + fmtBytes(s.size) })))));

  const st = r.storage || {};
  const storageItems = [...(st.localStorage || []).map((x) => ["localStorage", x]), ...(st.sessionStorage || []).map((x) => ["sessionStorage", x])];
  parts.push(section("Web Storage", storageItems.length, storageItems.map(([area, x]) => h("div", { class: "item" },
    h("span", { class: "tag", text: area }), h("code", { text: x.key }), h("div", { class: "meta", text: x.preview })))));

  parts.push(section("Custom globals (window.*)", r.globals?.length || 0, (r.globals || []).map((g) => h("div", { class: "item" },
    h("code", { text: "window." + g.name }), h("span", { class: "meta", text: "  " + g.type }),
    g.preview ? h("div", { class: "meta", text: g.preview }) : null))));

  el.replaceChildren(...parts);
}

// ---------- console ----------

async function refreshLogs() {
  try {
    const r = await send("READ_CONSOLE");
    state.logs = r?.logs || [];
    if (r && !r.hook) setStatus("Console capture isn't active on this tab yet — reload the page once.", true);
    renderLogs();
  } catch (e) { setStatus(e.message, true); }
}

function renderLogs() {
  const level = $("logLevel").value;
  const match = (l) => !level ||
    (level === "error" && /error|uncaught|unhandled/.test(l.level)) ||
    (level === "csp" && l.level === "csp-violation") ||
    (level === "warn" && l.level === "warn") ||
    (level === "log" && /^(log|info|debug)$/.test(l.level));
  const box = $("logs");
  box.replaceChildren(...state.logs.filter(match).slice(-300).map((l) =>
    h("div", { class: `log ${l.level}` }, h("span", { class: "lvl", text: `${new Date(l.ts).toLocaleTimeString()} ${l.level}` }), l.text)));
  box.scrollTop = box.scrollHeight;
}

const SNIPPETS = [
  { name: "Network requests made by the page", code: `(() => {\n  const rows = performance.getEntriesByType("resource").map(e => ({ type: e.initiatorType, url: e.name, ms: Math.round(e.duration), bytes: e.transferSize }));\n  console.table(rows);\n  return rows.filter(r => /fetch|xmlhttprequest|beacon/.test(r.type)).map(r => r.url);\n})()` },
  { name: "Forms and their fields", code: `[...document.forms].map(f => ({\n  action: f.action, method: f.method,\n  fields: [...f.elements].filter(e => e.name).map(e => \`\${e.type}:\${e.name}=\${String(e.value).slice(0, 40)}\`)\n}))` },
  { name: "JS-readable cookies", code: `document.cookie ? document.cookie.split("; ").map(c => c.split("=")[0]) : "No JS-readable cookies (good: they may all be HttpOnly)"` },
  { name: "Dump localStorage / sessionStorage", code: `({ local: { ...localStorage }, session: { ...sessionStorage } })` },
  { name: "Enable disabled / read-only controls", code: `(() => {\n  const els = document.querySelectorAll("[disabled],[readonly],[aria-disabled=true]");\n  els.forEach(e => { e.disabled = false; e.removeAttribute("disabled"); e.removeAttribute("readonly"); e.removeAttribute("aria-disabled"); e.style.outline = "2px dashed #f59e0b"; });\n  return els.length + " controls enabled (orange outline)";\n})()` },
  { name: "Watch DOM-XSS sinks live (innerHTML / document.write)", code: `(() => {\n  if (window.__dtaSinks) return "already watching";\n  window.__dtaSinks = true;\n  const d = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");\n  Object.defineProperty(Element.prototype, "innerHTML", {\n    configurable: true,\n    get() { return d.get.call(this); },\n    set(v) { if (/<|javascript:/i.test(v)) console.warn("[sink] innerHTML", this.tagName, String(v).slice(0, 200), new Error().stack.split("\\n").slice(2, 5).join(" | ")); return d.set.call(this, v); }\n  });\n  const w = document.write.bind(document);\n  document.write = (...a) => { console.warn("[sink] document.write", a.join("").slice(0, 200)); return w(...a); };\n  return "Watching. Interact with the page, then press Refresh above.";\n})()` },
  { name: "Service workers & caches", code: `(async () => ({\n  serviceWorkers: (await navigator.serviceWorker?.getRegistrations?.() || []).map(r => r.scope),\n  caches: await caches.keys()\n}))()` },
  { name: "postMessage listeners on window (DevTools panel only)", code: `(getEventListeners(window).message || []).map(l => l.listener.toString().slice(0, 600))`, devtools: true },
  { name: "Event listeners on selected element $0 (DevTools only)", code: `Object.fromEntries(Object.entries(getEventListeners($0)).map(([type, ls]) => [type, ls.map(l => l.listener.toString().slice(0, 300))]))`, devtools: true }
];

const NEEDS_CMDLINE_API = /\$0|\bgetEventListeners\(|\binspect\(|\bmonitorEvents\(|\bcopy\(|\bqueryObjects\(/;

async function runCode() {
  const code = $("code").value;
  const out = $("runOut");
  out.textContent = "Running…";
  try {
    if (IS_DEVTOOLS && NEEDS_CMDLINE_API.test(code)) {
      const result = await devtoolsEval(code);
      out.textContent = "✔ (DevTools eval)\n" + (typeof result === "string" ? result : JSON.stringify(result, null, 2));
      return;
    }
    if (!IS_DEVTOOLS && NEEDS_CMDLINE_API.test(code)) {
      out.textContent = "This code uses DevTools Command Line API ($0, getEventListeners…). Open DevTools → \"Security\" panel to run it.";
      return;
    }
    const r = await send("RUN_JS", { code });
    if (!r.ok && r.cspBlocked && IS_DEVTOOLS) {
      const result = await devtoolsEval(code);
      out.textContent = "✔ (page CSP blocks eval, used DevTools eval — promises are not awaited here)\n" + JSON.stringify(result, null, 2);
      return;
    }
    const lines = [r.ok ? "✔ Result:" : "✖ Error:", r.ok ? r.result : r.error];
    if (r.cspBlocked) lines.push("\nThe page's Content-Security-Policy blocks eval. Open DevTools (F12) → \"Security\" panel and run it there — DevTools bypasses CSP.");
    if (r.logs?.length) lines.push("\nConsole output:", ...r.logs.map((l) => `[${l.level}] ${l.text}`));
    out.textContent = lines.join("\n");
    refreshLogs();
  } catch (e) {
    out.textContent = "✖ " + e.message;
  }
}

// ---------- inspector ----------

const PATH_FN = `function(el){if(!el)return"";const p=[];while(el&&el.nodeType===1&&el!==document.documentElement&&p.length<10){if(el.id&&document.querySelectorAll("#"+CSS.escape(el.id)).length===1){p.unshift("#"+CSS.escape(el.id));break}let s=el.localName;const par=el.parentElement;if(par){const sib=[...par.children].filter(c=>c.localName===el.localName);if(sib.length>1)s+=":nth-of-type("+(sib.indexOf(el)+1)+")"}p.unshift(s);el=par}return p.join(" > ")}`;

async function readElement() {
  const selector = $("selector").value.trim();
  if (!selector) return setStatus("Enter a selector or pick an element.", true);
  try {
    const r = await send("READ_ELEMENT", { selector });
    if (IS_DEVTOOLS) {
      try {
        r.eventListeners = await devtoolsEval(`(() => { const e = document.querySelector(${JSON.stringify(selector)}); return e ? Object.fromEntries(Object.entries(getEventListeners(e)).map(([k, v]) => [k, v.length])) : null; })()`);
      } catch (_) { /* ignore */ }
    }
    $("elementOut").textContent = JSON.stringify(r, null, 2);
    setStatus(r.hiddenReason ? `Element is hidden (${r.hiddenReason}).` : "");
  } catch (e) { $("elementOut").textContent = "✖ " + e.message; }
}

async function writeElement() {
  const selector = $("selector").value.trim();
  if (!selector) return setStatus("Enter a selector first.", true);
  const operation = $("writeOp").value;
  if (operation === "remove" && !confirm("Remove this element from the page?")) return;
  try {
    const r = await send("WRITE_ELEMENT", { payload: { selector, operation, value: $("writeValue").value, attributeName: $("attrName").value.trim() } });
    $("elementOut").textContent = "✔ Applied\n" + (r.outerHTML || (r.removed ? "Element removed." : ""));
  } catch (e) { $("elementOut").textContent = "✖ " + e.message; }
}

// ---------- AI ----------

async function aiExplain() {
  $("aiOut").textContent = "Asking AI…";
  try {
    const r = await send("AI_EXPLAIN");
    $("aiOut").textContent = `(${r.model})\n\n${r.text}`;
  } catch (e) { $("aiOut").textContent = "✖ " + e.message; }
}

async function aiScript() {
  $("aiOut").textContent = "Generating…";
  try {
    const r = await send("AI_SCRIPT", { task: $("aiTask").value });
    $("code").value = r.text;
    $("aiOut").textContent = `Script generated with ${r.model}. Review it in the Console tab before running.`;
    switchTab("console");
  } catch (e) { $("aiOut").textContent = "✖ " + e.message; }
}

// ---------- settings ----------

async function loadSettings() {
  const s = await chrome.storage.local.get(["aiKeys", "geminiApiKeys", "aiModel", "activeChecks"]);
  $("aiKeys").value = (s.aiKeys || s.geminiApiKeys || []).join("\n");
  $("aiModel").value = s.aiModel || "auto";
  $("activeToggle").checked = Boolean(s.activeChecks);
}

async function saveSettings() {
  const keys = $("aiKeys").value.split(/[\s,]+/).map((k) => k.trim()).filter((k) => k.length > 20);
  await chrome.storage.local.set({ aiKeys: keys, aiModel: $("aiModel").value.trim() || "auto" });
  await chrome.storage.local.remove("geminiApiKeys");
  await chrome.storage.session.remove("modelCache").catch(() => {});
  $("settingsStatus").textContent = `Saved ${keys.length} key(s) locally.`;
}

// ---------- export ----------

function toMarkdown(r) {
  const lines = [`# Security scan: ${r.title || r.url}`, "", `- URL: ${r.url}`, `- Scanned: ${r.scannedAt}`, `- Summary: ${SEVS.map((s) => `${r.counts[s]} ${s}`).join(", ")}`, ""];
  for (const s of SEVS) {
    const fs = r.findings.filter((f) => f.severity === s);
    if (!fs.length) continue;
    lines.push(`## ${s.toUpperCase()} (${fs.length})`, "");
    for (const f of fs) {
      lines.push(`### ${f.title}`, `*${f.category}*`, "", f.description, "");
      if (f.evidence) lines.push("```", f.evidence, "```", "");
      if (f.recommendation) lines.push(`**Recommendation:** ${f.recommendation}`, "");
    }
  }
  return lines.join("\n");
}

function exportReport(kind) {
  const r = state.report;
  if (!r) return setStatus("Scan first.", true);
  const host = new URL(r.url).hostname.replace(/[^a-z0-9.-]/gi, "_");
  const stamp = r.scannedAt.slice(0, 19).replace(/[:T]/g, "-");
  if (kind === "md") download(`scan-${host}-${stamp}.md`, toMarkdown(r), "text/markdown");
  else download(`scan-${host}-${stamp}.json`, JSON.stringify(r, null, 2), "application/json");
}

// ---------- tabs & wiring ----------

function switchTab(name) {
  for (const b of $("tabs").children) b.classList.toggle("active", b.dataset.tab === name);
  for (const s of document.querySelectorAll(".tab")) s.classList.toggle("active", s.id === "tab-" + name);
  if (name === "console") refreshLogs();
}

function wire() {
  $("tabs").addEventListener("click", (e) => { const b = e.target.closest("button[data-tab]"); if (b) switchTab(b.dataset.tab); });
  $("scanBtn").addEventListener("click", () => busy($("scanBtn"), scan));
  $("activeToggle").addEventListener("change", () => chrome.storage.local.set({ activeChecks: $("activeToggle").checked }));
  $("search").addEventListener("input", renderFindings);
  $("exportMd").addEventListener("click", () => exportReport("md"));
  $("exportJson").addEventListener("click", () => exportReport("json"));

  $("onlyInteresting").addEventListener("change", renderHidden);
  $("revealInteresting").addEventListener("click", () => reveal(true, true));
  $("revealAll").addEventListener("click", () => reveal(true, false));
  $("restoreHidden").addEventListener("click", () => reveal(false));

  $("logLevel").addEventListener("change", renderLogs);
  $("refreshLogs").addEventListener("click", refreshLogs);
  for (const [i, s] of SNIPPETS.entries()) {
    if (s.devtools && !IS_DEVTOOLS) continue;
    $("snippets").append(h("option", { value: String(i), text: s.name }));
  }
  $("snippets").addEventListener("change", (e) => { const s = SNIPPETS[e.target.value]; if (s) $("code").value = s.code; e.target.value = ""; });
  $("runCode").addEventListener("click", () => busy($("runCode"), runCode));
  $("code").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); runCode(); } });
  $("runHint").textContent = IS_DEVTOOLS ? "Ctrl+Enter · $0 and getEventListeners() work here" : "Ctrl+Enter · runs in the page context";

  $("pickBtn").addEventListener("click", async () => {
    try { await send("START_PICKER"); setStatus("Click an element on the page (Esc to cancel)."); } catch (e) { setStatus(e.message, true); }
  });
  $("useSelected").addEventListener("click", async () => {
    try {
      const sel = await devtoolsEval(`(${PATH_FN})($0)`);
      if (!sel) return setStatus("Select an element in the Elements panel first.", true);
      $("selector").value = sel;
      readElement();
    } catch (e) { setStatus(e.message, true); }
  });
  $("readBtn").addEventListener("click", readElement);
  $("highlightBtn").addEventListener("click", () => highlight($("selector").value.trim()));
  $("revealInElements").addEventListener("click", () => showInElements($("selector").value.trim()));
  $("writeBtn").addEventListener("click", writeElement);

  $("aiExplain").addEventListener("click", () => busy($("aiExplain"), aiExplain));
  $("aiScript").addEventListener("click", () => busy($("aiScript"), aiScript));
  $("saveSettings").addEventListener("click", saveSettings);
  $("testAi").addEventListener("click", () => busy($("testAi"), async () => {
    $("settingsStatus").textContent = "Testing…";
    try {
      await saveSettings();
      const r = await send("AI_TEST");
      $("settingsStatus").textContent = `✔ Working — model ${r.model} replied "${r.text.slice(0, 30)}".`;
    } catch (e) { $("settingsStatus").textContent = "✖ " + e.message; }
  }));

  // Element picked on the page.
  chrome.runtime.onMessage.addListener((msg, sender) => {
    if (msg?.type === "DTA_PICKED" && sender.tab?.id === state.tabId) {
      $("selector").value = msg.selector;
      switchTab("inspector");
      readElement();
      setStatus("Picked " + msg.selector);
    }
  });

  // Follow tab changes / navigations.
  if (IS_DEVTOOLS) {
    chrome.devtools.network.onNavigated.addListener((url) => {
      state.url = url;
      $("target").textContent = url;
      state.report = null;
      renderAll();
      setStatus("Page navigated — scan again.");
    });
  } else {
    chrome.tabs.onActivated.addListener(({ windowId }) => { if (windowId === state.windowId) resolveTarget(); });
    chrome.tabs.onUpdated.addListener((tabId, info) => {
      if (tabId === state.tabId && (info.url || info.status === "complete")) resolveTarget();
    });
  }
}

async function init() {
  document.body.classList.toggle("devtools", IS_DEVTOOLS);
  $("mode").textContent = IS_DEVTOOLS ? "DevTools" : "Side panel";
  if (!IS_DEVTOOLS) {
    try { state.windowId = (await chrome.windows.getCurrent()).id; } catch (_) { /* ignore */ }
  }
  wire();
  await loadSettings();
  await resolveTarget();
}

init().catch((e) => setStatus("Init error: " + e.message, true));
