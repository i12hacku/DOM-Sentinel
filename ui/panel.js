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
  logs: [],
  triage: {},
  triageOrigin: null,
  view: "open",
  openRows: new Set(),
  diff: null
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

function setStatus(msg, isError = false, action) {
  const s = $("status");
  s.replaceChildren(msg || "");
  if (action) s.append(" ", h("button", { class: "link", text: action.label, onclick: () => action.fn() }));
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

function setTarget(url) {
  const el = $("target");
  el.title = url || "";
  let host = "No tab", path = "";
  try {
    const u = new URL(url);
    host = u.host || u.protocol;
    path = u.pathname + u.search;
  } catch (_) { host = url || "No tab"; }
  const parts = [h("span", { class: "host", text: host })];
  if (path && path !== "/") parts.push(h("span", { class: "path", text: path }));
  el.replaceChildren(...parts);
}

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
  setTarget(state.url);
  await loadReport();
}

async function loadReport() {
  state.report = null;
  try {
    const r = await send("GET_REPORT");
    if (r && sameDoc(r.url, state.url)) state.report = r;
  } catch (_) { /* ignore */ }
  state.openRows.clear();
  await loadTriage();
  await syncHistory(false);
  renderAll();
}

// ---------- scanning ----------

async function scan() {
  setStatus("Scanning headers, cookies, scripts and the DOM…");
  document.body.classList.add("scanning");
  const t = performance.now();
  try {
    const report = await send("SCAN", { options: { active: $("activeToggle").checked } });
    state.report = report;
    state.openRows.clear();
    await loadTriage();
    await syncHistory(true);
    const n = report.findings.length;
    setStatus(`Scanned in ${((performance.now() - t) / 1000).toFixed(1)}s. ${n} finding${n === 1 ? "" : "s"}.`);
    renderAll({ fresh: true });
  } finally {
    document.body.classList.remove("scanning");
  }
}

function renderAll(opts = {}) {
  renderSpectrum(opts.fresh);
  renderChanges();
  renderFindings();
  renderHidden();
  renderRecon();
  updateBadge();
}

// ---------- triage ----------
// Reviews are stored per origin in chrome.storage.local as
//   "triage:<origin>" -> { <fingerprint>: { status, at, title } }
// A fingerprint identifies "the same finding" across scans: category + title
// (numbers normalised, so "3 inline handlers" == "5 inline handlers") + selector.
// Secrets and cookies also include the first evidence line, so two different
// leaked keys with the same title are reviewed separately.

const TRIAGE = {
  confirmed: { label: "Confirmed", hint: "A real issue that needs fixing" },
  "false-positive": { label: "False positive", hint: "Not actually an issue. Hidden from the default view." },
  accepted: { label: "Accepted risk", hint: "Known and accepted for now. Hidden from the default view." }
};
const DISMISSED = new Set(["false-positive", "accepted"]);

function originOf(url) {
  try { const o = new URL(url).origin; return o && o !== "null" ? o : null; } catch (_) { return null; }
}

function fingerprint(f) {
  const parts = [f.category, String(f.title || "").replace(/\d+/g, "#"), f.selector || ""];
  if (f.category === "Secrets & tokens" || f.category === "Cookies") {
    parts.push(String(f.evidence || "").split("\n")[0].slice(0, 160));
  }
  return parts.join("|");
}

const statusOf = (f) => state.triage[fingerprint(f)]?.status || null;
const activeFindings = () => (state.report?.findings || []).filter((f) => !DISMISSED.has(statusOf(f)));

function countsOf(list) {
  const c = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of list) c[f.severity] += 1;
  return c;
}

function viewShows(f) {
  const status = statusOf(f);
  switch (state.view) {
    case "new": return isNew(f);
    case "fixed": return false;
    case "open": return !DISMISSED.has(status);
    case "all": return true;
    case "untriaged": return !status;
    default: return status === state.view;
  }
}

async function loadTriage() {
  state.triageOrigin = originOf(state.report?.url || state.url);
  state.triage = {};
  if (!state.triageOrigin) return;
  const key = "triage:" + state.triageOrigin;
  try { state.triage = (await chrome.storage.local.get(key))[key] || {}; } catch (_) { state.triage = {}; }
}

async function saveTriage() {
  if (!state.triageOrigin) return;
  const key = "triage:" + state.triageOrigin;
  if (Object.keys(state.triage).length) await chrome.storage.local.set({ [key]: state.triage });
  else await chrome.storage.local.remove(key);
}

async function setTriage(f, status) {
  if (!state.triageOrigin) return setStatus("Reviews can only be saved for http(s) pages.", true);
  const fp = fingerprint(f);
  const previous = state.triage[fp]?.status || null;
  if (status) state.triage[fp] = { status, at: Date.now(), title: f.title };
  else delete state.triage[fp];
  try { await saveTriage(); } catch (e) { return setStatus("Couldn't save the review: " + e.message, true); }
  renderSpectrum();
  renderFindings();
  updateBadge();
  if (!status) setStatus("Review cleared.");
  else if (!viewShows(f)) setStatus(`Marked as ${TRIAGE[status].label.toLowerCase()} and hidden.`, false, { label: "Undo", fn: () => setTriage(f, previous) });
  else setStatus(`Marked as ${TRIAGE[status].label.toLowerCase()}.`);
}

function showAllFindings() {
  state.view = "all";
  $("triageView").value = "all";
  renderFindings();
}

async function clearSiteTriage() {
  const origin = originOf(state.report?.url || state.url);
  if (!origin) return setStatus("Open an http(s) page first.", true);
  const n = Object.keys(state.triage).length;
  if (!n) { $("settingsStatus").textContent = `No reviews saved for ${origin}.`; return; }
  if (!confirm(`Delete all ${n} review${n === 1 ? "" : "s"} saved for ${origin}?`)) return;
  state.triage = {};
  await saveTriage();
  renderAll();
  $("settingsStatus").textContent = `Deleted ${n} review${n === 1 ? "" : "s"} for ${origin}.`;
}

function updateBadge() {
  const c = state.report ? countsOf(activeFindings()) : null;
  $("badge").textContent = c ? String(c.high + c.medium || "") : "";
}

// ---------- scan history & comparison ----------
// For every page (origin + path) we keep the latest two scan snapshots in
// chrome.storage.local as "history:<origin><path>" -> { latest, previous }.
// A snapshot is { at, url, items: [{ fp, title, category, severity }] }.
// The current report is compared with the snapshot taken before it.

const MAX_SNAPSHOT_ITEMS = 500;

function historyKey(url) {
  try {
    const u = new URL(url);
    return u.origin && u.origin !== "null" ? "history:" + u.origin + u.pathname : null;
  } catch (_) { return null; }
}

function snapshot(report) {
  return {
    at: report.scannedAt,
    url: report.url,
    items: report.findings.slice(0, MAX_SNAPSHOT_ITEMS).map((f) => ({ fp: fingerprint(f), title: f.title, category: f.category, severity: f.severity }))
  };
}

// record = true right after a new scan: rotate latest -> previous and save the new snapshot.
async function syncHistory(record) {
  state.diff = null;
  const r = state.report;
  const key = r && historyKey(r.url);
  if (!key) return;
  let entry = {};
  try { entry = (await chrome.storage.local.get(key))[key] || {}; } catch (_) { /* ignore */ }

  if (record && entry.latest?.at !== r.scannedAt) {
    entry = { previous: entry.latest || null, latest: snapshot(r) };
    try { await chrome.storage.local.set({ [key]: entry }); } catch (_) { /* storage full: compare without saving */ }
  }

  const base = entry.latest?.at === r.scannedAt ? entry.previous
    : entry.latest && entry.latest.at < r.scannedAt ? entry.latest
    : null;
  if (!base) { state.diff = { first: true, newFps: new Set(), fixed: [] }; return; }

  const current = new Set(r.findings.map(fingerprint));
  const before = new Set(base.items.map((i) => i.fp));
  state.diff = {
    first: false,
    baselineAt: base.at,
    newFps: new Set([...current].filter((fp) => !before.has(fp))),
    fixed: base.items.filter((i) => !current.has(i.fp)),
    unchanged: [...current].filter((fp) => before.has(fp)).length
  };
}

const isNew = (f) => Boolean(state.diff?.newFps?.has(fingerprint(f)));
const fmtWhen = (iso) => new Date(iso).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

function setView(view) {
  state.view = view;
  $("triageView").value = view;
  renderFindings();
}

function renderChanges() {
  const el = $("changes");
  const d = state.diff;
  if (!state.report || !d) { el.replaceChildren(); return; }
  if (d.first) { el.replaceChildren("First scan of this page. Scan it again later to see what changed."); return; }
  const n = d.newFps.size, m = d.fixed.length;
  if (!n && !m) { el.replaceChildren(`No changes since the scan on ${fmtWhen(d.baselineAt)}.`); return; }
  const parts = [`Since the scan on ${fmtWhen(d.baselineAt)}: `];
  if (n) parts.push(h("button", { class: "link change-new", title: "Show new findings", onclick: () => setView("new") }, `${n} new`));
  if (n && m) parts.push(", ");
  if (m) parts.push(h("button", { class: "link change-fixed", title: "Show fixed findings", onclick: () => setView("fixed") }, `${m} fixed`));
  parts.push(`, ${d.unchanged} unchanged.`);
  el.replaceChildren(...parts);
}

function renderFixed(list) {
  const d = state.diff;
  if (!d || d.first || !d.fixed.length) {
    list.replaceChildren(emptyState("Nothing fixed yet", d?.first ? "This is the first scan of this page, so there's nothing to compare with yet." : "Every finding from the last scan is still present."));
    return;
  }
  list.replaceChildren(h("details", { class: "group", open: true },
    h("summary", {}, `Fixed since ${fmtWhen(d.baselineAt)}`, h("span", { class: "count", text: String(d.fixed.length) })),
    h("div", { class: "sheet" }, d.fixed.map((i) => h("div", { class: `row finding fixed-item ${i.severity}` },
      h("div", { class: "head static" },
        h("span", { class: "title" }, h("span", { class: "title-text", text: i.title }), h("span", { class: "flag fixed", text: "Fixed" })),
        h("span", { class: "sev", text: i.severity })),
      h("p", { class: "fixed-meta", text: i.category })
    )))));
}

async function clearSiteHistory() {
  const origin = originOf(state.report?.url || state.url);
  if (!origin) return setStatus("Open an http(s) page first.", true);
  const all = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter((k) => k.startsWith("history:" + origin + "/"));
  if (!keys.length) { $("settingsStatus").textContent = `No scan history saved for ${origin}.`; return; }
  if (!confirm(`Delete scan history for ${keys.length} page${keys.length === 1 ? "" : "s"} on ${origin}?`)) return;
  await chrome.storage.local.remove(keys);
  state.diff = state.report ? { first: true, newFps: new Set(), fixed: [] } : null;
  renderAll();
  $("settingsStatus").textContent = `Deleted scan history for ${keys.length} page${keys.length === 1 ? "" : "s"} on ${origin}.`;
}



// ---------- threat spectrum (masthead) ----------

function toggleSev(s) {
  if (state.sevFilter.has(s)) state.sevFilter.delete(s); else state.sevFilter.add(s);
  if (!state.sevFilter.size) SEVS.forEach((x) => state.sevFilter.add(x)); // never filter everything away
  renderSpectrum();
  renderFindings();
}

function renderSpectrum(fresh) {
  const r = state.report;
  const bar = $("spectrum");
  const legend = $("summary");
  bar.className = "spectrum";
  if (!r) {
    bar.replaceChildren();
    bar.setAttribute("aria-label", "Not scanned yet");
    legend.replaceChildren(h("span", { class: "verdict", text: "Not scanned yet" }));
    return;
  }
  const counts = countsOf(activeFindings());
  const total = SEVS.reduce((n, s) => n + counts[s], 0);
  const dismissed = r.findings.length - total;
  const dismissedLink = dismissed ? h("button", { class: "dismissed", title: "Show dismissed findings", onclick: showAllFindings }, `${dismissed} dismissed`) : null;
  bar.setAttribute("aria-label", SEVS.map((s) => `${counts[s]} ${s}`).join(", ") + (dismissed ? `, ${dismissed} dismissed` : ""));
  if (!total) {
    bar.classList.add("clean");
    bar.replaceChildren();
    legend.replaceChildren(h("span", { class: "verdict", text: dismissed ? "Every finding has been dismissed." : "No findings on this page." }), dismissedLink || "");
    return;
  }
  bar.classList.add("has-data");
  if (fresh) bar.classList.add("fresh");
  bar.replaceChildren(...SEVS.filter((s) => counts[s]).map((s) => h("button", {
    class: `seg ${s}${state.sevFilter.has(s) ? "" : " off"}`,
    style: `flex: ${counts[s]} 1 0`,
    title: `${counts[s]} ${s}. Click to show or hide.`,
    tabindex: "-1",
    onclick: () => toggleSev(s)
  })));
  legend.replaceChildren(...SEVS.map((s) => h("button", {
    class: s,
    "aria-pressed": String(state.sevFilter.has(s)),
    title: `Show or hide ${s} findings`,
    onclick: () => toggleSev(s)
  }, h("b", { text: String(counts[s]) }), s)), dismissedLink || "");
}

// ---------- findings ----------

function emptyState(title, text, bullets) {
  return h("div", { class: "empty" },
    h("h2", { text: title }),
    h("p", { text }),
    bullets ? h("ul", {}, bullets.map((b) => h("li", { text: b }))) : null);
}

function renderFindings() {
  const r = state.report;
  const list = $("findings");
  if (!r) {
    list.replaceChildren(emptyState(
      "Scan this page to see its weak spots",
      "Scan page checks this tab and lists what it finds, worst first. Everything runs in your browser.",
      ["Security headers and cookie flags", "Secrets and tokens in scripts, storage and comments", "Hidden forms, links and admin controls", "Reflected input and other DOM XSS hints", "Outdated libraries with known vulnerabilities"]
    ));
    return;
  }
  const q = $("search").value.trim().toLowerCase();
  const reviewed = r.findings.filter((f) => statusOf(f)).length;
  $("reviewProgress").textContent = r.findings.length ? `${reviewed} of ${r.findings.length} reviewed` : "";
  if (state.view === "fixed") { renderFixed(list); return; }
  const shown = r.findings.filter((f) => state.sevFilter.has(f.severity) && viewShows(f) && (!q || `${f.title} ${f.category} ${f.description} ${f.evidence}`.toLowerCase().includes(q)));
  const groups = new Map();
  for (const f of shown) {
    if (!groups.has(f.category)) groups.set(f.category, []);
    groups.get(f.category).push(f);
  }
  const nodes = [];
  for (const [cat, items] of groups) {
    nodes.push(h("details", { class: "group", open: true },
      h("summary", {}, cat, h("span", { class: "count", text: String(items.length) })),
      h("div", { class: "sheet" }, items.map(findingRow))));
  }
  list.replaceChildren(...(nodes.length ? nodes : [emptyFindings(q)]));
}

function emptyFindings(q) {
  if (q) return emptyState("Nothing matches", `No findings contain "${q}". Clear the filter, or choose All findings in the review filter.`);
  if (state.view === "new") return emptyState("Nothing new", state.diff?.first ? "This is the first scan of this page, so there's nothing to compare with yet." : "No findings appeared since the last scan.");
  if (state.view === "untriaged") return emptyState("Everything is reviewed", "Every finding on this page has a review. Choose All findings to see them.");
  if (state.view === "open") return emptyState("Nothing left to review", "Every finding is marked as a false positive or an accepted risk, or its severity is switched off in the bar above.");
  if (state.view !== "all") return emptyState("No findings with this review", `No findings are marked as ${TRIAGE[state.view].label.toLowerCase()} yet.`);
  return emptyState("Nothing matches", "Every severity with findings is switched off. Click one in the bar above to show it again.");
}

function findingRow(f) {
  const status = statusOf(f);
  const fp = fingerprint(f);
  const row = h("div", { class: `row finding ${f.severity}${status ? " t-" + status : ""}${state.openRows.has(fp) ? " open" : ""}` });
  const actions = h("div", { class: "actions" });
  if (f.selector) {
    actions.append(h("button", { class: "link", text: "Highlight on page", onclick: () => highlight(f.selector) }));
    actions.append(h("button", { class: "link", text: "Open in Inspector", onclick: () => openInInspector(f.selector) }));
    if (IS_DEVTOOLS) actions.append(h("button", { class: "link", text: "Show in Elements", onclick: () => showInElements(f.selector) }));
  }
  actions.append(h("button", { class: "link", text: "Copy finding", onclick: () => copyText(findingText(f)) }));
  const head = h("button", {
    class: "head",
    "aria-expanded": String(state.openRows.has(fp)),
    onclick: () => {
      const open = row.classList.toggle("open");
      head.setAttribute("aria-expanded", String(open));
      if (open) state.openRows.add(fp); else state.openRows.delete(fp);
    }
  },
  h("span", { class: "title" },
    h("span", { class: "title-text", text: f.title }),
    isNew(f) ? h("span", { class: "flag new", text: "New" }) : null,
    status ? h("span", { class: `flag t-${status}`, text: TRIAGE[status].label }) : null),
  h("span", { class: "sev", text: f.severity }));
  const review = h("div", { class: "review", role: "group", "aria-label": "Review this finding" },
    Object.entries(TRIAGE).map(([key, t]) => h("button", {
      class: `review-btn t-${key}`,
      "aria-pressed": String(status === key),
      title: status === key ? "Click again to clear the review" : t.hint,
      text: t.label,
      onclick: () => setTriage(f, status === key ? null : key)
    })));
  row.append(head, h("div", { class: "body" },
    f.description ? h("p", { text: f.description }) : null,
    f.evidence ? h("pre", { text: f.evidence }) : null,
    f.recommendation ? h("div", { class: "fix" }, h("b", { text: "How to fix or verify" }), h("span", { text: f.recommendation })) : null,
    review,
    actions));
  return row;
}

const findingText = (f) => `[${f.severity.toUpperCase()}] ${f.title}\nCategory: ${f.category}${statusOf(f) ? "\nReview: " + TRIAGE[statusOf(f)].label : ""}\n\n${f.description}\n\nEvidence:\n${f.evidence || "-"}\n\nRecommendation: ${f.recommendation || "-"}`;

async function highlight(selector, ref) {
  try {
    const r = await send("HIGHLIGHT", { selector, ref });
    setStatus(r?.hidden ? `That element is hidden (${r.hidden}). Reveal it to see it.` : "Highlighted on the page.");
  } catch (e) { setStatus(e.message, true); }
}

async function showInElements(selector) {
  try {
    const found = await devtoolsEval(`(() => { const e = document.querySelector(${JSON.stringify(selector)}); if (e) inspect(e); return !!e; })()`);
    setStatus(found ? "Selected in the Elements panel." : "Element not found. The page may have changed; scan again.", !found);
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
  if (!r) {
    $("hiddenSummary").textContent = "";
    list.replaceChildren(emptyState("No scan yet", "Scan the page to list its hidden elements."));
    return;
  }
  const only = $("onlyInteresting").checked;
  const items = (r.hidden || []).filter((x) => !only || x.interesting);
  const interesting = (r.hidden || []).filter((x) => x.interesting).length;
  $("hiddenSummary").textContent = `${r.hiddenTotal} hidden element${r.hiddenTotal === 1 ? "" : "s"}, ${interesting} worth a look.`;
  if (!items.length) {
    list.replaceChildren(emptyState(only ? "Nothing suspicious is hidden" : "No hidden elements", only ? "No hidden forms, inputs, links or sensitive keywords. Untick the filter to see every hidden element." : "This page doesn't hide any content."));
    return;
  }
  list.replaceChildren(h("div", { class: "sheet" }, items.map((x) => h("div", { class: "row item" },
    h("div", { class: "line" },
      x.interesting ? h("span", { class: "flag warn", text: "Worth a look" }) : x.isWidget ? h("span", { class: "flag", text: "UI widget" }) : null,
      h("span", { class: "flag", text: x.reason }),
      h("code", { text: x.selector })),
    x.why.length ? h("div", { class: "meta", text: "Contains " + x.why.join(", ") }) : null,
    x.text ? h("div", { class: "meta", text: `Text: ${x.text}` }) : null,
    h("details", {}, h("summary", { text: "HTML source" }), h("pre", { class: "out", text: x.html })),
    h("div", { class: "actions" },
      h("button", { class: "link", text: "Reveal", onclick: () => reveal(true, false, x.ref) }),
      h("button", { class: "link", text: "Highlight", onclick: () => highlight(x.selector, x.ref) }),
      h("button", { class: "link", text: "Open in Inspector", onclick: () => openInInspector(x.selector) }),
      IS_DEVTOOLS ? h("button", { class: "link", text: "Show in Elements", onclick: () => showInElements(x.selector) }) : null)
  ))));
}

async function reveal(on, onlyInteresting, ref) {
  try {
    const r = await send("REVEAL_HIDDEN", { on, onlyInteresting, ref });
    if (on) setStatus(r.revealed ? `Revealed ${r.revealed} element${r.revealed === 1 ? "" : "s"}, outlined in pink. Restore puts them back.` : "Nothing to reveal. The page changed since the scan; scan again.", !r.revealed);
    else setStatus(`Restored ${r.restored} element${r.restored === 1 ? "" : "s"}.`);
    if (on && typeof ref === "number") highlight(null, ref);
  } catch (e) { setStatus(e.message, true); }
}

// ---------- recon ----------

function section(title, count, ...content) {
  return h("details", { class: "group" }, h("summary", {}, title, count != null ? h("span", { class: "count", text: String(count) }) : null), ...content);
}

function kv(pairs) {
  return h("div", { class: "kv" }, pairs.flatMap(([k, v]) => [h("span", { text: k }), h("code", { text: v })]));
}

const rows = (items, fn) => (items.length ? h("div", { class: "sheet" }, items.map((x) => h("div", { class: "row item" }, fn(x)))) : h("p", { class: "note", text: "None found." }));

function renderRecon() {
  const r = state.report;
  const el = $("recon");
  if (!r) { el.replaceChildren(emptyState("No scan yet", "Scan the page to see its headers, cookies, libraries, endpoints and scripts.")); return; }
  const parts = [];

  parts.push(h("div", { class: "sheet" }, kv([
    ["Scanned", new Date(r.scannedAt).toLocaleString() + ` (${(r.durationMs / 1000).toFixed(1)}s)`],
    ["Elements", String(r.stats?.elements)],
    ["Forms, scripts, iframes", `${r.stats?.forms}, ${r.stats?.scripts}, ${r.stats?.iframes}`],
    ["Console capture", r.consoleHook ? "On" : "Off. Reload the page to turn it on."],
    ["Active checks", r.activeChecks ? "Included" : "Not run"]
  ])));

  if (r.headers) parts.push(section("Response headers", r.headers.list.length,
    h("div", { class: "sheet" }, h("p", { class: "note", style: "padding: 8px 12px 0; margin: 0", text: `HTTP ${r.headers.statusCode}, captured via ${r.headers.via}` }), kv(r.headers.list.map((x) => [x.name, x.value])))));

  parts.push(section("Cookies", r.cookies.length, rows(r.cookies, (c) => [
    h("div", { class: "line" },
      h("code", { text: c.name }),
      h("span", { class: "flag " + (c.httpOnly ? "good" : "warn"), text: c.httpOnly ? "HttpOnly" : "Readable by JS" }),
      h("span", { class: "flag " + (c.secure ? "good" : "warn"), text: c.secure ? "Secure" : "Not Secure" }),
      h("span", { class: "flag", text: "SameSite " + c.sameSite }),
      h("span", { class: "flag", text: c.session ? "Session" : "Persistent" })),
    h("div", { class: "meta", text: `${c.domain}${c.path}, ${c.size} characters` })])));

  parts.push(section("Libraries", r.libraries?.length || 0, rows(r.libraries || [], (l) =>
    h("div", { class: "line" }, h("b", { text: l.name }), h("code", { text: l.version || "version unknown" }), h("span", { class: "meta", text: "detected via " + l.how })))));

  const ep = r.endpoints || [];
  parts.push(section("Endpoints and URLs in code", ep.length,
    ep.length ? h("div", { class: "toolbar" }, h("button", { class: "btn", text: "Copy all URLs", onclick: () => copyText(ep.map((e) => e.url).join("\n")) })) : null,
    rows(ep, (e) => [
      h("div", { class: "line" },
        e.interesting ? h("span", { class: "flag warn", text: "Worth a look" }) : null,
        e.external ? h("span", { class: "flag", text: "External" }) : null,
        h("code", { text: e.url })),
      h("div", { class: "meta", text: "Found in " + e.from })])));

  parts.push(section("Scripts", r.scripts?.length || 0, rows(r.scripts || [], (s) =>
    h("div", { class: "line" }, h("span", { class: "flag", text: s.sameSite ? "First-party" : "Third-party" }), h("code", { text: s.url }), h("span", { class: "meta", text: fmtBytes(s.size) })))));

  const st = r.storage || {};
  const storageItems = [...(st.localStorage || []).map((x) => ["localStorage", x]), ...(st.sessionStorage || []).map((x) => ["sessionStorage", x])];
  parts.push(section("Web Storage", storageItems.length, rows(storageItems, ([area, x]) => [
    h("div", { class: "line" }, h("span", { class: "flag", text: area }), h("code", { text: x.key })),
    h("div", { class: "meta", text: x.preview })])));

  parts.push(section("Custom globals on window", r.globals?.length || 0, rows(r.globals || [], (g) => [
    h("div", { class: "line" }, h("code", { text: "window." + g.name }), h("span", { class: "meta", text: g.type })),
    g.preview ? h("div", { class: "meta", text: g.preview }) : null])));

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

const LEVEL_NAMES = { "csp-violation": "CSP", "resource-error": "load fail", uncaught: "uncaught", unhandledrejection: "rejection" };

function renderLogs() {
  const level = $("logLevel").value;
  const match = (l) => !level ||
    (level === "error" && /error|uncaught|unhandled/.test(l.level)) ||
    (level === "csp" && l.level === "csp-violation") ||
    (level === "warn" && l.level === "warn") ||
    (level === "log" && /^(log|info|debug)$/.test(l.level));
  const box = $("logs");
  box.replaceChildren(...state.logs.filter(match).slice(-300).map((l) =>
    h("div", { class: `log ${l.level}`, title: new Date(l.ts).toLocaleTimeString() }, h("span", { class: "lvl", text: LEVEL_NAMES[l.level] || l.level }), h("span", { text: l.text }))));
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
    const excludeIds = (state.report?.findings || []).filter((f) => DISMISSED.has(statusOf(f))).map((f) => f.id);
    const r = await send("AI_EXPLAIN", { excludeIds });
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
  const active = activeFindings();
  const dismissed = r.findings.filter((f) => DISMISSED.has(statusOf(f)));
  const counts = countsOf(active);
  const reviewed = r.findings.filter((f) => statusOf(f)).length;
  const lines = [
    `# Security scan: ${r.title || r.url}`, "",
    `- URL: ${r.url}`,
    `- Scanned: ${r.scannedAt}`,
    `- Open findings: ${SEVS.map((s) => `${counts[s]} ${s}`).join(", ")}`,
    `- Reviewed: ${reviewed} of ${r.findings.length}${dismissed.length ? ` (${dismissed.length} dismissed, listed at the end)` : ""}`,
    state.diff && !state.diff.first ? `- Since ${state.diff.baselineAt}: ${state.diff.newFps.size} new, ${state.diff.fixed.length} fixed, ${state.diff.unchanged} unchanged` : "- Changes: first scan of this page",
    ""
  ];
  const item = (f) => {
    const st = statusOf(f);
    lines.push(`### ${f.title}`, `*${f.category}*${isNew(f) ? " · **New**" : ""}${st ? ` · **${TRIAGE[st].label}**` : ""}`, "", f.description, "");
    if (f.evidence) lines.push("```", f.evidence, "```", "");
    if (f.recommendation) lines.push(`**Recommendation:** ${f.recommendation}`, "");
  };
  for (const s of SEVS) {
    const fs = active.filter((f) => f.severity === s);
    if (!fs.length) continue;
    lines.push(`## ${s.toUpperCase()} (${fs.length})`, "");
    fs.forEach(item);
  }
  if (dismissed.length) {
    lines.push(`## Dismissed (${dismissed.length})`, "");
    for (const f of dismissed) lines.push(`- **${TRIAGE[statusOf(f)].label}** · ${f.severity} · ${f.title}`);
    lines.push("");
  }
  if (state.diff?.fixed?.length) {
    lines.push(`## Fixed since last scan (${state.diff.fixed.length})`, "");
    for (const i of state.diff.fixed) lines.push(`- ${i.severity} · ${i.title} (${i.category})`);
    lines.push("");
  }
  return lines.join("\n");
}

function exportReport(kind) {
  const r = state.report;
  if (!r) return setStatus("Scan first.", true);
  const host = new URL(r.url).hostname.replace(/[^a-z0-9.-]/gi, "_");
  const stamp = r.scannedAt.slice(0, 19).replace(/[:T]/g, "-");
  if (kind === "md") download(`scan-${host}-${stamp}.md`, toMarkdown(r), "text/markdown");
  else {
    const d = state.diff;
    const withReviews = {
      ...r,
      findings: r.findings.map((f) => ({ ...f, review: statusOf(f), isNew: isNew(f) })),
      changes: d && !d.first ? { comparedWith: d.baselineAt, new: d.newFps.size, fixed: d.fixed, unchanged: d.unchanged } : null
    };
    download(`scan-${host}-${stamp}.json`, JSON.stringify(withReviews, null, 2), "application/json");
  }
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
  $("triageView").addEventListener("change", (e) => { state.view = e.target.value; renderFindings(); });
  $("clearTriage").addEventListener("click", clearSiteTriage);
  $("clearHistory").addEventListener("click", clearSiteHistory);
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
      setTarget(url);
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
  if (IS_DEVTOOLS && chrome.devtools.panels?.themeName) {
    document.documentElement.dataset.theme = chrome.devtools.panels.themeName === "dark" ? "dark" : "light";
  }
  $("mode").textContent = IS_DEVTOOLS ? "in DevTools" : "";
  if (!IS_DEVTOOLS) {
    try { state.windowId = (await chrome.windows.getCurrent()).id; } catch (_) { /* ignore */ }
  }
  wire();
  await loadSettings();
  await resolveTarget();
}

init().catch((e) => setStatus("Init error: " + e.message, true));
