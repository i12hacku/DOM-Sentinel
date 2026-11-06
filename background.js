import {
  analyzeHeaders, analyzeCookies, scanSecrets, scanCodePatterns, extractEndpoints,
  analyzeLibraries, analyzeConsole, ACTIVE_PROBES
} from "./lib/rules.js";
import { callAi, streamAi, explainPrompt, scriptPrompt, stripFences } from "./lib/ai.js";

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
const MAX_EXTERNAL_SCRIPTS = 40;
const MAX_SCRIPT_BYTES = 3_000_000;

// ---------- setup ----------

chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
});
chrome.runtime.onStartup.addListener(() => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
});

// Capture main-frame response headers (incl. Set-Cookie) for every tab.
chrome.webRequest.onHeadersReceived.addListener(
  (d) => {
    if (d.tabId < 0 || d.frameId !== 0) return;
    chrome.storage.session.set({
      [`hdr:${d.tabId}`]: { url: d.url, statusCode: d.statusCode, headers: d.responseHeaders || [], at: Date.now(), via: "webRequest" }
    }).catch(() => {});
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["responseHeaders", "extraHeaders"]
);

// Tell open panels about address changes, including single-page-app route changes
// (history.pushState / hash routes) that don't reload the page.
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (!info.url) return;
  chrome.runtime.sendMessage({ type: "DTA_URL", tabId, url: info.url }).catch(() => { /* no panel open */ });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([`hdr:${tabId}`, `report:${tabId}`]).catch(() => {});
});

// ---------- message router ----------

const handlers = {
  SCAN: ({ tabId, options }) => scanTab(tabId, options || {}),
  GET_REPORT: async ({ tabId }) => (await chrome.storage.session.get(`report:${tabId}`))[`report:${tabId}`] || null,
  HIGHLIGHT: ({ tabId, selector, ref }) => agent(tabId, "highlight", [selector, ref]),
  REVEAL_HIDDEN: ({ tabId, on, onlyInteresting, ref }) => agent(tabId, "revealHidden", [on, onlyInteresting, ref]),
  READ_ELEMENT: ({ tabId, selector }) => agent(tabId, "readElement", [selector]),
  WRITE_ELEMENT: ({ tabId, payload }) => agent(tabId, "writeElement", [payload]),
  START_PICKER: ({ tabId }) => agent(tabId, "startPicker", []),
  READ_CONSOLE: ({ tabId }) => readConsole(tabId),
  RUN_JS: ({ tabId, code }) => runJs(tabId, code),
  AI_EXPLAIN: async ({ tabId, excludeIds }) => {
    const report = await handlers.GET_REPORT({ tabId });
    if (!report) throw new Error("Run a scan first.");
    const skip = new Set(Array.isArray(excludeIds) ? excludeIds : []);
    return callAi(explainPrompt({ ...report, findings: report.findings.filter((f) => !skip.has(f.id)) }), { temperature: 0.2 });
  },
  AI_SCRIPT: async ({ tabId, task }) => {
    if (!task?.trim()) throw new Error("Describe what the script should do.");
    const report = await handlers.GET_REPORT({ tabId });
    const res = await callAi(scriptPrompt(task, report), { temperature: 0.25 });
    return { ...res, text: stripFences(res.text) };
  },
  AI_TEST: () => callAi("Reply with exactly: OK", { maxOutputTokens: 2048 })
};

// Streaming AI: the panel opens a port named "ai", sends one request, and receives
// { type: "status" | "text" | "reset" | "done" | "error" } messages. Closing the port cancels.
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "ai") return;
  const ctrl = new AbortController();
  port.onDisconnect.addListener(() => ctrl.abort());
  const post = (m) => { try { port.postMessage(m); } catch (_) { /* panel closed */ } };
  port.onMessage.addListener(async (msg) => {
    try {
      const report = await handlers.GET_REPORT({ tabId: msg.tabId });
      let prompt, opts;
      const isScript = msg.kind === "script";
      if (isScript) {
        if (!msg.task?.trim()) throw new Error("Describe what the script should do.");
        prompt = scriptPrompt(msg.task, report);
        opts = { temperature: 0.25, maxOutputTokens: 4096, fast: true };
      } else {
        if (!report) throw new Error("Run a scan first.");
        const skip = new Set(Array.isArray(msg.excludeIds) ? msg.excludeIds : []);
        prompt = explainPrompt({ ...report, findings: report.findings.filter((f) => !skip.has(f.id)) });
        opts = { temperature: 0.2, fast: Boolean(msg.fast) };
      }
      const res = await streamAi(prompt, opts, {
        signal: ctrl.signal,
        onText: (text) => post({ type: "text", text }),
        onStatus: (text) => post({ type: "status", text }),
        onReset: () => post({ type: "reset" })
      });
      post({ type: "done", model: res.model, text: isScript ? stripFences(res.text) : res.text });
    } catch (e) {
      if (!ctrl.signal.aborted) post({ type: "error", error: e.message || String(e) });
    }
  });
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const handler = handlers[msg?.type];
  if (!handler) return false; // not for us (e.g. DTA_PICKED goes to the UI)
  Promise.resolve()
    .then(() => handler(msg, sender))
    .then((data) => sendResponse({ ok: true, data }))
    .catch((e) => sendResponse({ ok: false, error: friendlyError(e) }));
  return true;
});

function friendlyError(e) {
  const m = e?.message || String(e);
  if (/Cannot access|cannot be scripted|chrome:\/\/|edge:\/\/|chrome-extension:\/\/|The extensions gallery/i.test(m)) {
    return "This page cannot be scanned (browser-internal page or Web Store). Open a normal http(s) site.";
  }
  if (/No tab with id|Frame with ID 0 was removed/i.test(m)) return "The tab was closed or navigated. Try again.";
  return m;
}

// ---------- page helpers ----------

async function agent(tabId, method, args) {
  if (typeof tabId !== "number") throw new Error("No target tab.");
  await chrome.scripting.executeScript({ target: { tabId }, files: ["injected/page-agent.js"] });
  const [res] = await chrome.scripting.executeScript({
    target: { tabId },
    func: (m, a) => globalThis.__DTA_AGENT__[m](...a),
    args: [method, args]
  });
  const r = res?.result;
  if (r && r.ok === false) throw new Error(r.error);
  return r;
}

async function inMain(tabId, func, args = []) {
  const [res] = await chrome.scripting.executeScript({ target: { tabId }, world: "MAIN", func, args });
  return res?.result;
}

// Runs in the page MAIN world: library versions, custom globals, captured logs.
function collectMainWorld() {
  const out = { libraries: [], globals: [], logs: [], hook: !!window.__DTA_HOOK__, frameworkData: [] };
  const lib = (name, version, how) => out.libraries.push({ name, version: version ? String(version) : null, how });
  const t = (f) => { try { return f(); } catch (_) { return undefined; } };
  const w = window;

  t(() => w.jQuery?.fn?.jquery && lib("jQuery", w.jQuery.fn.jquery, "jQuery.fn.jquery"));
  t(() => w.angular?.version?.full && lib("AngularJS", w.angular.version.full, "angular.version"));
  t(() => { const e = document.querySelector("[ng-version]"); if (e) lib("Angular", e.getAttribute("ng-version"), "[ng-version]"); });
  t(() => {
    if (w.React?.version) lib("React", w.React.version, "window.React");
    else if (document.querySelector("[data-reactroot], #__next, #root") && [...document.querySelectorAll("body *")].slice(0, 300).some((e) => Object.keys(e).some((k) => k.startsWith("__react")))) lib("React", null, "fiber keys");
  });
  t(() => { const v = w.Vue?.version || document.querySelector("[data-v-app]")?.__vue_app__?.version; if (v || w.__VUE__) lib("Vue", v, "Vue"); });
  t(() => typeof w._?.chunk === "function" && w._.VERSION && lib("lodash", w._.VERSION, "_.VERSION"));
  t(() => w.moment?.version && lib("moment", w.moment.version, "moment.version"));
  t(() => w.Handlebars?.VERSION && lib("Handlebars", w.Handlebars.VERSION, "Handlebars.VERSION"));
  t(() => { const v = w.bootstrap?.Tooltip?.VERSION || w.jQuery?.fn?.tooltip?.Constructor?.VERSION; if (v) lib("Bootstrap", v, "Tooltip.VERSION"); });
  t(() => w.DOMPurify?.version && lib("DOMPurify", w.DOMPurify.version, "DOMPurify.version"));
  t(() => w.Prototype?.Version && lib("Prototype", w.Prototype.Version, "Prototype.Version"));
  t(() => w.Ember?.VERSION && lib("Ember", w.Ember.VERSION, "Ember.VERSION"));
  t(() => w.Backbone?.VERSION && lib("Backbone", w.Backbone.VERSION, "Backbone.VERSION"));
  t(() => { if (w.__NEXT_DATA__) { lib("Next.js", w.next?.version, "__NEXT_DATA__"); out.frameworkData.push({ origin: "window.__NEXT_DATA__", text: JSON.stringify(w.__NEXT_DATA__).slice(0, 300000) }); } });
  t(() => { if (w.__NUXT__) { lib("Nuxt", null, "__NUXT__"); out.frameworkData.push({ origin: "window.__NUXT__", text: JSON.stringify(w.__NUXT__).slice(0, 300000) }); } });
  t(() => w.firebase && lib("Firebase", w.firebase.SDK_VERSION, "window.firebase"));

  // Custom globals = keys not present on a pristine window.
  t(() => {
    const f = document.createElement("iframe");
    f.style.display = "none";
    document.documentElement.appendChild(f);
    const clean = new Set(Object.getOwnPropertyNames(f.contentWindow));
    f.remove();
    const interesting = /(config|env|setting|secret|token|key|api|auth|debug|user|session|firebase|credential|endpoint|feature|flag|store|state)/i;
    for (const k of Object.getOwnPropertyNames(w)) {
      if (clean.has(k) || k.startsWith("__DTA") || /^(webkit|on)/.test(k) || out.globals.length >= 300) continue;
      const v = t(() => w[k]);
      const type = v === null ? "null" : typeof v;
      const g = { name: k, type };
      if (interesting.test(k) && type !== "function") {
        g.preview = t(() => {
          const seen = new WeakSet();
          return JSON.stringify(v, (key, val) => {
            if (typeof val === "object" && val !== null) { if (seen.has(val)) return "[circular]"; seen.add(val); }
            return typeof val === "function" ? "[fn]" : val;
          });
        })?.slice(0, 20000) ?? String(v).slice(0, 2000);
      }
      out.globals.push(g);
    }
  });

  out.logs = (w.__DTA_HOOK__?.logs || []).slice(-300);
  return out;
}

async function readConsole(tabId) {
  return inMain(tabId, () => ({ hook: !!window.__DTA_HOOK__, logs: (window.__DTA_HOOK__?.logs || []).slice(-400) }));
}

async function runJs(tabId, code) {
  if (!String(code || "").trim()) throw new Error("Nothing to run.");
  return inMain(tabId, async (src) => {
    const hook = window.__DTA_HOOK__;
    const startSeq = hook ? hook.seq : 0;
    const ser = (v) => {
      if (v === undefined) return "undefined";
      if (typeof v === "string") return v;
      if (v instanceof Element) return v.outerHTML.slice(0, 3000);
      try { return JSON.stringify(v, null, 2)?.slice(0, 20000) ?? String(v); } catch (_) { return String(v); }
    };
    const logs = () => (hook ? hook.logs.filter((l) => l.seq > startSeq) : []);
    try {
      let r = (0, eval)(src);
      if (r && typeof r.then === "function") r = await r;
      return { ok: true, result: ser(r), logs: logs() };
    } catch (e) {
      const msg = String(e?.stack || e);
      return { ok: false, error: msg, cspBlocked: e instanceof EvalError || /unsafe-eval|Content Security Policy/i.test(msg), logs: logs() };
    }
  }, [code]);
}

async function fetchText(url, { timeout = 8000, maxBytes = MAX_SCRIPT_BYTES, wantBytes = false } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, { credentials: "omit", cache: "no-store", signal: ctrl.signal, redirect: "follow" });
    const buf = new Uint8Array(await res.arrayBuffer()).slice(0, maxBytes);
    return { status: res.status, url: res.url, type: res.headers.get("content-type") || "", text: new TextDecoder().decode(buf), bytes: wantBytes ? buf.slice(0, 16) : null };
  } finally {
    clearTimeout(timer);
  }
}

// ---------- scan ----------

async function scanTab(tabId, options) {
  const t0 = Date.now();
  let tab = await chrome.tabs.get(tabId);
  for (let i = 0; i < 40 && tab.status === "loading"; i++) { // wait up to 10s for a reload to finish
    await new Promise((r) => setTimeout(r, 250));
    tab = await chrome.tabs.get(tabId);
  }
  if (!/^https?:|^file:/.test(tab.url || "")) throw new Error("This page cannot be scanned (browser-internal page). Open a normal http(s) site.");

  const page = await agent(tabId, "collect", []);
  const main = (await inMain(tabId, collectMainWorld).catch(() => null)) || { libraries: [], globals: [], logs: [], frameworkData: [] };
  const findings = [...page.findings];
  const pageOrigin = new URL(page.url).origin;

  // Headers: prefer webRequest capture for this URL, else re-fetch from the page.
  let headers = (await chrome.storage.session.get(`hdr:${tabId}`))[`hdr:${tabId}`];
  if (!headers || headers.url.split("#")[0] !== page.url.split("#")[0]) {
    const viaFetch = await agent(tabId, "fetchHeaders", []).catch(() => null);
    if (viaFetch?.ok) headers = viaFetch;
  }
  findings.push(...analyzeHeaders(headers, page.url, page.cspMeta));

  // Cookies (sees HttpOnly too).
  const cookies = await chrome.cookies.getAll({ url: page.url }).catch(() => []);
  findings.push(...analyzeCookies(cookies, page.url));

  // Sources for secret/endpoint/code scanning.
  const sources = page.sources.map((s) => ({ ...s, code: s.inline && !/json|template|html|text\/x-/i.test(s.origin) }));
  for (const fd of main.frameworkData || []) sources.push(fd);
  for (const g of main.globals || []) if (g.preview) sources.push({ origin: `window.${g.name}`, text: g.preview });
  for (const l of main.logs || []) sources.push({ origin: "console", text: l.text });

  // Fetch external scripts from the extension (not blocked by page CORS).
  const scriptUrls = [...new Set(page.scriptUrls)].filter((u) => /^https?:/.test(u)).slice(0, MAX_EXTERNAL_SCRIPTS);
  const scripts = [];
  await Promise.all(scriptUrls.map(async (url) => {
    try {
      const r = await fetchText(url);
      if (r.status !== 200) return;
      const sameSite = new URL(url).origin === pageOrigin;
      scripts.push({ url, size: r.text.length, sameSite });
      sources.push({ origin: url.split("?")[0], text: r.text, code: sameSite });
      const sm = r.text.slice(-500).match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)\s*$/);
      if (sm && !sm[1].startsWith("data:")) {
        const mapUrl = new URL(sm[1], url).href;
        const m = await fetchText(mapUrl, { maxBytes: 4000, timeout: 5000 }).catch(() => null);
        if (m?.status === 200 && /"mappings"\s*:/.test(m.text)) {
          findings.push({ category: "Information disclosure", severity: sameSite ? "low" : "info", title: `Source map exposed: ${mapUrl.split("/").pop().split("?")[0]}`, description: "Source maps let anyone reconstruct the original, un-minified source code (comments, internal names, hidden routes).", evidence: mapUrl, recommendation: "Don't deploy .map files publicly (or restrict them). Open DevTools → Sources to browse the original code." });
        }
      }
    } catch (_) { /* unreachable script — ignore */ }
  }));

  findings.push(...scanSecrets(sources));
  findings.push(...scanCodePatterns(sources));
  findings.push(...analyzeLibraries(main.libraries || []));
  findings.push(...analyzeConsole(main.logs || []));

  const endpoints = extractEndpoints(sources, page.url);
  const interestingEndpoints = endpoints.filter((e) => e.interesting && !e.external);
  if (interestingEndpoints.length) {
    findings.push({ category: "Recon", severity: "info", title: `${interestingEndpoints.length} interesting endpoint(s) referenced in code`, description: "API/admin/auth routes found in HTML and JavaScript. Hidden routes are worth testing for missing authorization.", evidence: interestingEndpoints.slice(0, 60).map((e) => e.url).join("\n"), recommendation: "See the Recon tab for the full list." });
  }

  const suspiciousGlobals = (main.globals || []).filter((g) => g.preview && /(secret|token|key|debug|credential|auth)/i.test(g.name));
  if (suspiciousGlobals.length) {
    findings.push({ category: "Information disclosure", severity: "low", title: `${suspiciousGlobals.length} suspicious global variable(s)`, description: "Global objects with names suggesting configuration or credentials are exposed to every script on the page.", evidence: suspiciousGlobals.map((g) => `window.${g.name} = ${g.preview.slice(0, 200)}`).join("\n"), recommendation: "Make sure no secrets are included in client-side configuration." });
  }

  // Opt-in active probes.
  if (options.active && /^https?:/.test(page.url)) findings.push(...(await activeChecks(pageOrigin)));

  // Dedupe + sort.
  const seen = new Set();
  const final = findings
    .filter((f) => { const k = `${f.category}|${f.title}|${String(f.evidence).slice(0, 200)}`; if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])
    .map((f, i) => ({ ...f, id: i }));

  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of final) counts[f.severity] += 1;

  const report = {
    url: page.url,
    title: page.title,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - t0,
    activeChecks: !!options.active,
    counts,
    findings: final,
    hidden: page.hidden,
    hiddenTotal: page.hiddenTotal,
    storage: page.storage,
    cookies: cookies.map((c) => ({ name: c.name, domain: c.domain, path: c.path, httpOnly: c.httpOnly, secure: c.secure, sameSite: c.sameSite, session: !c.expirationDate, size: c.value.length })),
    headers: headers ? { via: headers.via, statusCode: headers.statusCode, list: (headers.headers || []).map((h) => ({ name: h.name, value: /set-cookie/i.test(h.name) ? h.value.replace(/=([^;]{6})[^;]*/, "=$1…") : h.value })) } : null,
    libraries: main.libraries,
    globals: (main.globals || []).map(({ name, type, preview }) => ({ name, type, preview: preview?.slice(0, 300) })),
    scripts,
    endpoints,
    consoleHook: main.hook,
    stats: page.stats,
    roots: page.roots || null
  };
  await chrome.storage.session.set({ [`report:${tabId}`]: report }).catch(() => {});
  return report;
}

async function activeChecks(origin) {
  const out = [];
  // Baseline to detect "soft 404" pages that return 200 for everything.
  const baseline = await fetchText(`${origin}/dta-${Math.random().toString(36).slice(2)}-404`, { maxBytes: 60000, timeout: 6000 }).catch(() => null);
  await Promise.all(ACTIVE_PROBES.map(async (p) => {
    const r = await fetchText(origin + p.path, { maxBytes: 60000, timeout: 6000, wantBytes: true }).catch(() => null);
    const softHit = r && baseline && baseline.status === 200 && Math.abs(r.text.length - baseline.text.length) < 50;
    const hit = r && r.status === 200 && !softHit && p.test(r.text, r.bytes);
    if (p.invert ? !hit : hit) {
      out.push({ category: "Exposed files (active)", severity: p.sev, title: p.title, description: p.desc, evidence: `${origin}${p.path} → HTTP ${r?.status ?? "error"}\n${p.evidence && r ? p.evidence(r.text) : (r?.text || "").slice(0, 300)}`, recommendation: p.invert ? "Publish /.well-known/security.txt (RFC 9116)." : "Block public access to this path on the web server." });
    }
  }));
  return out;
}
