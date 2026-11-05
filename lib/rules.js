// Pure analysis functions used by the background service worker.
// Each returns an array of findings: {category, severity, title, description, evidence, recommendation}

const clip = (s, n = 300) => {
  s = String(s ?? "");
  return s.length > n ? s.slice(0, n) + "…" : s;
};

export const mask = (s) => (s.length <= 12 ? s.slice(0, 3) + "…" : `${s.slice(0, 6)}…${s.slice(-4)} (${s.length} chars)`);

// ---------------- Security headers ----------------

export function analyzeHeaders(capture, pageUrl, cspMeta) {
  const out = [];
  const url = new URL(pageUrl);
  const isHttps = url.protocol === "https:";
  const h = {};
  for (const { name, value } of capture?.headers || []) {
    const k = name.toLowerCase();
    h[k] = h[k] ? `${h[k]}\n${value}` : value;
  }
  const add = (severity, title, description, evidence, recommendation) =>
    out.push({ category: "Security headers", severity, title, description, evidence, recommendation });

  if (url.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) {
    out.push({ category: "Transport", severity: "high", title: "Page served over plain HTTP", description: "Everything on this page — including cookies and form data — can be read and modified on the network.", evidence: pageUrl, recommendation: "Redirect all traffic to HTTPS and enable HSTS." });
  }

  // CSP
  const csp = h["content-security-policy"] || cspMeta || "";
  if (!csp) {
    add(h["content-security-policy-report-only"] ? "low" : "medium", "No Content-Security-Policy", "Without CSP, any injected script (XSS) runs with full privileges.", h["content-security-policy-report-only"] ? `Report-only policy present:\n${clip(h["content-security-policy-report-only"], 500)}` : "Header absent", "Add a strict CSP, e.g. script-src 'nonce-…' 'strict-dynamic'; object-src 'none'; base-uri 'none'.");
  } else {
    const dirs = Object.fromEntries(csp.split(";").map((d) => d.trim().split(/\s+/)).filter((p) => p[0]).map((p) => [p[0].toLowerCase(), p.slice(1)]));
    const script = dirs["script-src"] || dirs["default-src"] || [];
    const hasNonceOrHash = script.some((s) => /^'(nonce|sha256|sha384|sha512)-/.test(s));
    if (script.includes("'unsafe-inline'") && !hasNonceOrHash) add("medium", "CSP allows 'unsafe-inline' scripts", "Inline script injection (the most common XSS) is not blocked by this policy.", clip(csp, 600), "Replace 'unsafe-inline' with nonces or hashes.");
    if (script.includes("'unsafe-eval'")) add("low", "CSP allows 'unsafe-eval'", "eval()/new Function() are allowed, which helps many DOM-XSS gadgets.", clip(csp, 600), "Remove 'unsafe-eval' if possible.");
    if (script.some((s) => s === "*" || s === "https:" || s === "http:" || s === "data:")) add("medium", "CSP script-src is overly broad", "Wildcard, scheme-only or data: sources let attackers load script from almost anywhere.", clip(csp, 600), "List exact hosts, or use nonces with 'strict-dynamic'.");
    if (!dirs["object-src"] && !(dirs["default-src"] || []).includes("'none'")) add("low", "CSP missing object-src", "Plugins/embeds are not restricted.", clip(csp, 600), "Add object-src 'none'.");
    if (!dirs["base-uri"]) add("low", "CSP missing base-uri", "An injected <base> tag can redirect relative script URLs.", clip(csp, 600), "Add base-uri 'none' or 'self'.");
    if (!h["content-security-policy"] && cspMeta) add("info", "CSP is only set via <meta>", "Meta CSP cannot use frame-ancestors, report-uri or sandbox.", clip(cspMeta, 400), "Send CSP as an HTTP header.");
  }

  // HSTS
  if (isHttps) {
    const hsts = h["strict-transport-security"];
    if (!hsts) add("medium", "No Strict-Transport-Security (HSTS)", "First visits and typed URLs can be downgraded to HTTP by a network attacker.", "Header absent", "Add Strict-Transport-Security: max-age=31536000; includeSubDomains");
    else {
      const age = Number((hsts.match(/max-age=(\d+)/i) || [])[1] || 0);
      if (age < 15552000) add("low", "HSTS max-age is short", `max-age=${age}s (< 180 days).`, hsts, "Use max-age=31536000 or more.");
    }
  }

  // Clickjacking
  const xfo = h["x-frame-options"];
  if (!xfo && !/frame-ancestors/i.test(h["content-security-policy"] || "")) {
    add("medium", "Page can be framed (clickjacking)", "Neither X-Frame-Options nor CSP frame-ancestors is set, so another site can load this page in an invisible iframe and trick users into clicking.", "Headers absent", "Add CSP frame-ancestors 'self' (or X-Frame-Options: DENY).");
  }

  if ((h["x-content-type-options"] || "").toLowerCase() !== "nosniff") add("low", "Missing X-Content-Type-Options: nosniff", "Browsers may MIME-sniff responses into executable types.", h["x-content-type-options"] || "Header absent", "Add X-Content-Type-Options: nosniff");
  if (!h["referrer-policy"]) add("info", "No Referrer-Policy header", "Browser default (strict-origin-when-cross-origin) applies; full URLs may still leak same-origin.", "Header absent", "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).");
  if (!h["permissions-policy"]) add("info", "No Permissions-Policy header", "Powerful features (camera, geolocation…) are not explicitly restricted for embedded content.", "Header absent", "Add a Permissions-Policy disabling unused features.");

  for (const k of ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime", "x-debug-token", "x-debug-token-link"]) {
    if (h[k] && (/\d/.test(h[k]) || k.startsWith("x-debug") || k === "x-powered-by")) {
      add(k.startsWith("x-debug") ? "medium" : "low", `Technology disclosure: ${k}`, "Exact software/version helps attackers pick known exploits.", `${k}: ${h[k]}`, "Remove or genericise this header.");
    }
  }

  const acao = h["access-control-allow-origin"];
  if (acao) {
    const creds = /true/i.test(h["access-control-allow-credentials"] || "");
    if (acao === "*" && creds) add("high", "CORS: wildcard origin with credentials", "Invalid but dangerous configuration.", `ACAO: ${acao}\nACAC: true`, "Allow-list specific origins.");
    else if (creds && acao !== url.origin) add("medium", "CORS allows credentialed requests from another origin", "Check whether the server reflects arbitrary Origin values.", `ACAO: ${acao}\nACAC: true`, "Send a request with Origin: https://evil.example and confirm it is not reflected.");
    else if (acao === "*") add("info", "CORS: Access-Control-Allow-Origin: *", "Any site can read this response (without cookies).", acao, "Fine for public data; avoid on authenticated responses.");
  }

  for (const line of (h["set-cookie"] || "").split("\n").filter(Boolean)) {
    const name = line.split("=")[0].trim();
    const missing = [];
    if (!/;\s*secure/i.test(line) && isHttps) missing.push("Secure");
    if (!/;\s*httponly/i.test(line)) missing.push("HttpOnly");
    if (!/;\s*samesite/i.test(line)) missing.push("SameSite");
    if (missing.length && isSessionName(name)) {
      add("medium", `Set-Cookie "${name}" missing ${missing.join(", ")}`, "Session cookie set without protective flags.", clip(line.replace(/=([^;]{6})[^;]*/, "=$1…"), 300), "Set Secure; HttpOnly; SameSite=Lax (or Strict).");
    }
  }

  if (!capture) {
    out.push({ category: "Security headers", severity: "info", title: "Response headers not available", description: "Reload the page with the extension enabled so headers can be captured.", evidence: "", recommendation: "Reload the tab, then scan again." });
  }
  return out;
}

const isSessionName = (n) => /(sess|sid|auth|token|jwt|login|remember|user|account|csrf|xsrf|connect\.sid|phpsessid|jsessionid|asp\.net)/i.test(n);

// ---------------- Cookies (chrome.cookies) ----------------

export function analyzeCookies(cookies, pageUrl) {
  const out = [];
  const isHttps = pageUrl.startsWith("https:");
  for (const c of cookies) {
    const sessionLike = isSessionName(c.name) || looksLikeJwt(c.value) || (c.value.length >= 24 && /^[A-Za-z0-9%._-]+$/.test(c.value) && !c.expirationDate);
    const problems = [];
    if (!c.httpOnly) problems.push("not HttpOnly (readable by JavaScript / XSS)");
    if (isHttps && !c.secure) problems.push("not Secure (sent over HTTP)");
    if (c.sameSite === "no_restriction") problems.push("SameSite=None (sent on cross-site requests)");
    if (c.sameSite === "unspecified") problems.push("no SameSite attribute");
    if (sessionLike && problems.length) {
      out.push({
        category: "Cookies",
        severity: !c.httpOnly || (isHttps && !c.secure) ? "medium" : "low",
        title: `Cookie "${c.name}" is ${problems[0].split(" (")[0]}${problems.length > 1 ? ` (+${problems.length - 1} more)` : ""}`,
        description: `This looks like a session/auth cookie and is ${problems.join("; ")}.`,
        evidence: `${c.name}=${mask(c.value)}\ndomain=${c.domain} path=${c.path} httpOnly=${c.httpOnly} secure=${c.secure} sameSite=${c.sameSite}${c.expirationDate ? " expires=" + new Date(c.expirationDate * 1000).toISOString() : " (session)"}`,
        recommendation: "Set HttpOnly; Secure; SameSite=Lax on session cookies."
      });
    }
    if (looksLikeJwt(c.value)) out.push(...analyzeJwt(c.value, `cookie "${c.name}"`));
  }
  return out;
}

// ---------------- JWT ----------------

const looksLikeJwt = (v) => /^eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*$/.test(String(v || ""));

function b64urlJson(part) {
  try {
    const s = part.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(decodeURIComponent(escape(atob(s + "===".slice((s.length + 3) % 4)))));
  } catch (_) { return null; }
}

export function analyzeJwt(token, where) {
  const [h, p, sig] = token.split(".");
  const header = b64urlJson(h);
  const payload = b64urlJson(p);
  if (!header) return [];
  const out = [];
  const alg = String(header.alg || "");
  const summary = `header: ${JSON.stringify(header)}\npayload: ${clip(JSON.stringify(payload), 600)}`;
  if (/^none$/i.test(alg) || !sig) {
    out.push({ category: "Secrets & tokens", severity: "high", title: `Unsigned JWT (alg=${alg || "none"}) in ${where}`, description: "If the server accepts unsigned tokens, anyone can forge identities.", evidence: summary, recommendation: "Reject alg=none server-side and pin the expected algorithm." });
  }
  if (payload) {
    const sensitive = Object.keys(payload).filter((k) => /(pass|secret|ssn|card|cvv|private)/i.test(k));
    if (sensitive.length) out.push({ category: "Secrets & tokens", severity: "medium", title: `JWT in ${where} contains sensitive claims`, description: "JWT payloads are only base64-encoded, not encrypted. Anyone holding it can read them.", evidence: summary, recommendation: "Remove sensitive data from token claims." });
    if (payload.exp && payload.iat && payload.exp - payload.iat > 60 * 60 * 24 * 30) out.push({ category: "Secrets & tokens", severity: "low", title: `Long-lived JWT in ${where}`, description: `Token lifetime is ${Math.round((payload.exp - payload.iat) / 86400)} days.`, evidence: summary, recommendation: "Use short-lived access tokens with refresh rotation." });
  }
  return out;
}

// ---------------- Secrets ----------------

const SECRET_RULES = [
  { name: "AWS access key ID", re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, sev: "high" },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, sev: "medium", note: "Browser keys are often intentionally public — confirm it is restricted by HTTP referrer and API." },
  { name: "GitHub token", re: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g, sev: "high" },
  { name: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, sev: "high" },
  { name: "Slack webhook", re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/g, sev: "high" },
  { name: "Stripe secret key", re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g, sev: "high" },
  { name: "OpenAI API key", re: /\bsk-(proj-)?[A-Za-z0-9_-]{40,}\b/g, sev: "high" },
  { name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{30,}\b/g, sev: "high" },
  { name: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, sev: "high" },
  { name: "Twilio API key", re: /\bSK[0-9a-f]{32}\b/g, sev: "medium" },
  { name: "Mailgun API key", re: /\bkey-[0-9a-f]{32}\b/g, sev: "medium" },
  { name: "Private key block", re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/g, sev: "high" },
  { name: "Basic-auth credentials in URL", re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/"'`]{2,}:[^\s:@/"'`]{3,}@[a-z0-9.-]+/gi, sev: "high" },
  { name: "JSON Web Token", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g, sev: "medium", jwt: true },
  {
    name: "Hard-coded credential",
    re: /["']?([A-Za-z0-9_]*(?:api[_-]?key|apikey|secret|passwd|password|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key)[A-Za-z0-9_]*)["']?\s*[:=]\s*["'`]([^"'`\s]{8,200})["'`]/gi,
    sev: "medium",
    group: 2
  }
];

const PLACEHOLDER = /^(x+|\*+|\.+|<.*>|\{\{.*\}\}|\$\{.*\}|your[_-]?|example|placeholder|changeme|undefined|null|true|false|password|secret|test|demo|sample|xxx)/i;

export function scanSecrets(sources) {
  const found = new Map();
  for (const src of sources) {
    const text = src.text || "";
    for (const rule of SECRET_RULES) {
      rule.re.lastIndex = 0;
      let m;
      let guard = 0;
      while ((m = rule.re.exec(text)) && guard++ < 50) {
        const value = rule.group ? m[rule.group] : m[0];
        if (rule.group && (PLACEHOLDER.test(value) || /^[a-z]+$/i.test(value) || /^(function|return|this\.|e\.|t\.|n\.)/.test(value))) continue;
        const key = rule.name + "|" + value;
        if (found.has(key)) { found.get(key).where.add(src.origin); continue; }
        const ctx = text.slice(Math.max(0, m.index - 60), m.index + m[0].length + 60).replace(value, mask(value)).replace(/\s+/g, " ");
        found.set(key, { rule, value, where: new Set([src.origin]), ctx });
      }
    }
  }
  const out = [];
  for (const { rule, value, where, ctx } of found.values()) {
    if (rule.jwt) {
      const jwtFindings = analyzeJwt(value, [...where][0]);
      out.push({ category: "Secrets & tokens", severity: "medium", title: `JWT exposed in ${[...where][0]}`, description: "A bearer token is embedded in page content or storage. Anyone who can read it can impersonate the user until it expires.", evidence: `${mask(value)}\nfound in: ${[...where].slice(0, 5).join(", ")}`, recommendation: "Keep tokens out of HTML/JS/storage where possible; use HttpOnly cookies." }, ...jwtFindings);
      continue;
    }
    out.push({
      category: "Secrets & tokens",
      severity: rule.sev,
      title: `${rule.name} exposed`,
      description: `A value matching "${rule.name}" is shipped to the browser.${rule.note ? " " + rule.note : " Anything sent to the client is public."}`,
      evidence: `${mask(value)}\nfound in: ${[...where].slice(0, 5).join(", ")}\ncontext: …${clip(ctx, 260)}…`,
      recommendation: "Revoke/rotate the credential and move it server-side. Verify scope before reporting (some keys are public by design)."
    });
  }
  return out;
}

// ---------------- DOM XSS source→sink patterns ----------------

const SINK = /(\.innerHTML\s*[+]?=|\.outerHTML\s*=|document\.write(ln)?\s*\(|insertAdjacentHTML\s*\(|\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*["'`]|\$\([^)]*\)\.(html|append|prepend|after|before)\s*\(|dangerouslySetInnerHTML|v-html|\.srcdoc\s*=)/;
const SOURCE = /(location\.(hash|search|href)|document\.(URL|documentURI|referrer|baseURI)|window\.name|URLSearchParams|\.getParameter\(|postMessage|event\.data|e\.data)/;

export function scanCodePatterns(sources) {
  const out = [];
  const flows = [];
  const pmNoOrigin = [];
  let sinkCount = 0;
  for (const src of sources) {
    if (!src.code) continue;
    const text = src.text;
    const sinkRe = new RegExp(SINK.source, "g");
    let m;
    let guard = 0;
    while ((m = sinkRe.exec(text)) && guard++ < 200) {
      sinkCount += 1;
      const win = text.slice(Math.max(0, m.index - 250), m.index + 250);
      const s = SOURCE.exec(win);
      if (s && flows.length < 25) flows.push(`${src.origin}: …${win.slice(Math.max(0, 250 - 120), 250 + 120).replace(/\s+/g, " ")}…`);
    }
    const pmRe = /addEventListener\(\s*["']message["']/g;
    while ((m = pmRe.exec(text))) {
      const body = text.slice(m.index, m.index + 800);
      if (!/\.origin\b/.test(body) && pmNoOrigin.length < 10) pmNoOrigin.push(`${src.origin}: …${body.slice(0, 220).replace(/\s+/g, " ")}…`);
    }
  }
  if (flows.length) out.push({ category: "DOM XSS hints", severity: "medium", title: `${flows.length} possible source→sink flow(s) in JavaScript`, description: "User-controllable data (URL, referrer, postMessage…) appears close to a dangerous HTML/JS sink. This is a heuristic — confirm by tracing the code.", evidence: flows.join("\n\n"), recommendation: "Set a breakpoint on the sink in DevTools → Sources, feed a marker through the source, and check whether it reaches the sink unsanitized. Use textContent / DOMPurify / Trusted Types." });
  if (pmNoOrigin.length) out.push({ category: "DOM XSS hints", severity: "low", title: "postMessage listener without an origin check", description: "Any website that can open/frame this page could send it messages.", evidence: pmNoOrigin.join("\n\n"), recommendation: "Check event.origin against an allow-list before using event.data." });
  if (sinkCount && !flows.length) out.push({ category: "DOM XSS hints", severity: "info", title: `${sinkCount} HTML/JS sink call(s) in page scripts`, description: "No obvious URL-source nearby, but these are the places to review for DOM XSS.", evidence: "", recommendation: "Prefer textContent/setAttribute; enable Trusted Types." });
  return out;
}

// ---------------- Endpoints ----------------

const NOISE_HOST = /(w3\.org|schema\.org|xmlns|example\.(com|org)|purl\.org|mozilla\.org\/MPL|apache\.org\/licenses|opensource\.org|github\.com\/[^/]+\/[^/]+\/(issues|blob)|reactjs\.org\/docs|fb\.me|googleapis\.com\/css)/i;
const STATIC_EXT = /\.(png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|otf|mp4|webm|mp3|map)(\?|$)/i;
const INTERESTING_PATH = /(api|graphql|admin|internal|auth|login|logout|token|oauth|upload|debug|v\d+\/|user|account|config|private|backup|export|import|webhook|rpc|ws)/i;

export function extractEndpoints(sources, pageUrl) {
  const set = new Map();
  const add = (val, origin) => {
    if (val.length < 3 || val.length > 300 || STATIC_EXT.test(val) || NOISE_HOST.test(val)) return;
    if (!set.has(val)) set.set(val, origin);
  };
  for (const src of sources) {
    const text = src.text || "";
    for (const m of text.matchAll(/https?:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:\/[^\s"'`<>\\)]{0,200})?/g)) add(m[0], src.origin);
    for (const m of text.matchAll(/["'`](\/(?:[A-Za-z0-9_.~-]+|\{[^}]{1,30}\}|\$\{[^}]{1,30}\}|:[A-Za-z_]+)(?:\/(?:[A-Za-z0-9_.~-]+|\{[^}]{1,30}\}|\$\{[^}]{1,30}\}|:[A-Za-z_]+))*\/?(?:\?[^"'`\s]{0,80})?)["'`]/g)) {
      if (m[1].length > 1 && !m[1].startsWith("//")) add(m[1], src.origin);
    }
  }
  const origin = new URL(pageUrl).origin;
  return [...set.entries()]
    .map(([url, from]) => ({ url, from, interesting: INTERESTING_PATH.test(url), external: /^https?:/.test(url) && !url.startsWith(origin) }))
    .sort((a, b) => Number(b.interesting) - Number(a.interesting) || Number(a.external) - Number(b.external))
    .slice(0, 400);
}

// ---------------- Libraries ----------------

const VULN_LIBS = [
  { name: "jQuery", below: "3.5.0", sev: "medium", note: "CVE-2020-11022 / CVE-2020-11023: XSS when passing untrusted HTML to .html(), .append() etc." },
  { name: "AngularJS", below: "999", sev: "medium", note: "AngularJS 1.x is end-of-life (Dec 2021) and has known template-injection/sandbox-escape XSS issues." },
  { name: "lodash", below: "4.17.21", sev: "medium", note: "CVE-2021-23337 (command injection in _.template), CVE-2020-8203 (prototype pollution)." },
  { name: "moment", below: "2.29.4", sev: "low", note: "CVE-2022-31129 (ReDoS), CVE-2022-24785 (path traversal)." },
  { name: "Bootstrap", below: "3.4.1", sev: "medium", note: "CVE-2019-8331 / CVE-2018-14042: XSS via data-template / data-target attributes." },
  { name: "Bootstrap", min: "4.0.0", below: "4.3.1", sev: "medium", note: "CVE-2019-8331: XSS in tooltip/popover data-template." },
  { name: "Handlebars", below: "4.7.7", sev: "medium", note: "CVE-2021-23369 / CVE-2021-23383: code execution via crafted templates." },
  { name: "DOMPurify", below: "2.5.4", sev: "medium", note: "Several mutation-XSS bypasses fixed in 2.5.x / 3.1.x." },
  { name: "DOMPurify", min: "3.0.0", below: "3.1.3", sev: "medium", note: "Mutation-XSS bypasses fixed in 3.1.3+." },
  { name: "Prototype", below: "1.7.3", sev: "low", note: "Old Prototype.js versions have known XSS/prototype issues." }
];

export function compareVersions(a, b) {
  const pa = String(a).split(/[^0-9]+/).filter(Boolean).map(Number);
  const pb = String(b).split(/[^0-9]+/).filter(Boolean).map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

export function analyzeLibraries(libs) {
  const out = [];
  for (const lib of libs) {
    if (!lib.version) continue;
    for (const rule of VULN_LIBS) {
      if (rule.name !== lib.name) continue;
      if (rule.min && compareVersions(lib.version, rule.min) < 0) continue;
      if (compareVersions(lib.version, rule.below) < 0) {
        out.push({ category: "Vulnerable libraries", severity: rule.sev, title: `${lib.name} ${lib.version} has known vulnerabilities`, description: rule.note, evidence: `${lib.name} ${lib.version} (detected via ${lib.how})`, recommendation: `Upgrade ${lib.name}${rule.below !== "999" ? " to ≥ " + rule.below : " to a supported framework"}. Exploitability depends on how the app uses it — verify before reporting.` });
      }
    }
  }
  return out;
}

// ---------------- Console ----------------

export function analyzeConsole(logs) {
  const out = [];
  const csp = logs.filter((l) => l.level === "csp-violation");
  const errors = logs.filter((l) => ["error", "uncaught", "unhandledrejection"].includes(l.level));
  if (csp.length) out.push({ category: "Console", severity: "info", title: `${csp.length} CSP violation(s) captured`, description: "Blocked resources/inline code. Shows which parts of the policy are enforced and what the page tried to load.", evidence: [...new Set(csp.map((l) => l.text))].slice(0, 20).join("\n"), recommendation: "Review whether blocked items are attacks or legit resources missing from the policy." });
  if (errors.length) out.push({ category: "Console", severity: "info", title: `${errors.length} JavaScript error(s) captured`, description: "Errors can reveal stack traces, internal file paths and API details.", evidence: [...new Set(errors.map((l) => l.text))].slice(0, 15).map((t) => clip(t, 300)).join("\n"), recommendation: "Open the Console tab for details." });
  const debug = logs.filter((l) => /(password|token|secret|api[_-]?key|bearer|authorization)/i.test(l.text));
  if (debug.length) out.push({ category: "Console", severity: "low", title: `${debug.length} console message(s) mention credentials`, description: "Apps that log tokens/passwords leak them to anyone with DevTools (and to logging extensions).", evidence: debug.slice(0, 10).map((l) => clip(l.text, 200)).join("\n"), recommendation: "Remove sensitive debug logging in production builds." });
  return out;
}

// ---------------- Active checks (opt-in) ----------------

export const ACTIVE_PROBES = [
  { path: "/.git/HEAD", sev: "high", title: "Git repository exposed (/.git/)", desc: "The full source code and history can usually be downloaded.", test: (t) => /^ref: refs\//.test(t) || /^[0-9a-f]{40}\s*$/.test(t) },
  { path: "/.env", sev: "high", title: "Environment file exposed (/.env)", desc: ".env files usually contain database passwords and API keys.", test: (t) => !/^\s*</.test(t) && /^[A-Z][A-Z0-9_]{2,}=/m.test(t) },
  { path: "/.DS_Store", sev: "low", title: ".DS_Store file exposed", desc: "Reveals directory listings from a developer's Mac.", test: (t, bytes) => bytes && bytes[0] === 0 && bytes[3] === 1 && bytes[4] === 0x42 && bytes[5] === 0x75 },
  { path: "/server-status", sev: "medium", title: "Apache server-status exposed", desc: "Shows live requests, client IPs and internal URLs.", test: (t) => /Apache Server Status/i.test(t) },
  { path: "/phpinfo.php", sev: "medium", title: "phpinfo() page exposed", desc: "Discloses configuration, paths and sometimes secrets.", test: (t) => /phpinfo\(\)|<title>PHP \d/i.test(t) },
  { path: "/swagger.json", sev: "low", title: "API specification exposed (swagger.json)", desc: "Lists every API endpoint and parameter.", test: (t) => /"(swagger|openapi)"\s*:/.test(t) },
  { path: "/openapi.json", sev: "low", title: "API specification exposed (openapi.json)", desc: "Lists every API endpoint and parameter.", test: (t) => /"(swagger|openapi)"\s*:/.test(t) },
  { path: "/v2/api-docs", sev: "low", title: "API specification exposed (/v2/api-docs)", desc: "Lists every API endpoint and parameter.", test: (t) => /"(swagger|openapi)"\s*:/.test(t) },
  { path: "/wp-json/wp/v2/users", sev: "low", title: "WordPress user enumeration", desc: "Usernames are listed publicly, helping brute-force attacks.", test: (t) => /^\s*\[\s*\{[\s\S]*"slug"/.test(t) },
  { path: "/crossdomain.xml", sev: "low", title: "Permissive crossdomain.xml", desc: "Allows any domain (legacy Flash/PDF clients) to read responses.", test: (t) => /domain="\*"/.test(t) },
  { path: "/robots.txt", sev: "info", title: "robots.txt lists hidden paths", desc: "Disallowed paths often point to admin or private areas.", test: (t) => /^\s*disallow:\s*\/\S+/im.test(t), evidence: (t) => t.split(/\r?\n/).filter((l) => /^\s*disallow:/i.test(l)).slice(0, 40).join("\n") },
  { path: "/.well-known/security.txt", sev: "info", invert: true, title: "No security.txt", desc: "There is no published way for researchers to report vulnerabilities.", test: (t) => /contact:/i.test(t) }
];
