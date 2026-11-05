// Runs in the page's MAIN world at document_start so it sees errors and logs
// from the very first script. Stores a capped ring buffer on window.__DTA_HOOK__.
(() => {
  if (window.__DTA_HOOK__) return;

  const MAX = 500;
  const logs = [];
  let seq = 0;

  const toText = (v) => {
    try {
      if (typeof v === "string") return v;
      if (v instanceof Error) return v.stack || String(v);
      if (v instanceof Element) return `<${v.localName}${v.id ? "#" + v.id : ""}>`;
      const s = JSON.stringify(v);
      return s === undefined ? String(v) : s;
    } catch (_) {
      try { return String(v); } catch (_) { return "[unserializable]"; }
    }
  };

  const push = (level, args, extra) => {
    try {
      seq += 1;
      logs.push({ seq, ts: Date.now(), level, text: args.map(toText).join(" ").slice(0, 4000), ...extra });
      if (logs.length > MAX) logs.splice(0, logs.length - MAX);
    } catch (_) { /* never break the page */ }
  };

  for (const level of ["log", "info", "warn", "error", "debug"]) {
    const original = console[level];
    if (typeof original !== "function") continue;
    console[level] = function (...args) {
      push(level, args);
      return original.apply(this, args);
    };
  }

  window.addEventListener("error", (e) => {
    const t = e.target;
    if (t && t !== window && t.tagName) {
      push("resource-error", [`Failed to load <${t.tagName.toLowerCase()}> ${t.src || t.href || ""}`]);
    } else {
      push("uncaught", [e.message, `${e.filename || "?"}:${e.lineno || 0}:${e.colno || 0}`]);
    }
  }, true);

  window.addEventListener("unhandledrejection", (e) => push("unhandledrejection", [e.reason]));

  window.addEventListener("securitypolicyviolation", (e) => {
    push("csp-violation", [`'${e.violatedDirective}' blocked ${e.blockedURI || "inline code"}`], {
      directive: e.violatedDirective,
      blocked: e.blockedURI,
      source: `${e.sourceFile || ""}:${e.lineNumber || 0}`
    });
  }, true);

  Object.defineProperty(window, "__DTA_HOOK__", {
    value: { logs, get seq() { return seq; } },
    enumerable: false
  });
})();
