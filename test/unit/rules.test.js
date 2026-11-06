// Unit tests for lib/rules.js (pure functions). Run with: npm test
// Fake secrets are built by concatenation so secret scanners don't flag this file.
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeHeaders, analyzeCookies, analyzeJwt, scanSecrets, scanCodePatterns,
  extractEndpoints, analyzeLibraries, compareVersions, analyzeConsole, ACTIVE_PROBES, mask
} from "../../lib/rules.js";

const titles = (findings) => findings.map((f) => f.title);
const find = (findings, re) => findings.find((f) => re.test(f.title));
const headers = (obj) => ({ headers: Object.entries(obj).map(([name, value]) => ({ name, value })) });
const b64url = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (header, payload, sig = "c2lnbmF0dXJl") => `${b64url(header)}.${b64url(payload)}.${sig}`;

describe("analyzeHeaders", () => {
  test("flags a missing CSP, HSTS and framing protection on HTTPS", () => {
    const f = analyzeHeaders(headers({}), "https://shop.test/", null);
    assert.equal(find(f, /No Content-Security-Policy/).severity, "medium");
    assert.ok(find(f, /Strict-Transport-Security/));
    assert.ok(find(f, /clickjacking/));
  });

  test("flags plain HTTP as high, except on localhost", () => {
    assert.equal(find(analyzeHeaders(headers({}), "http://shop.test/", null), /plain HTTP/).severity, "high");
    assert.equal(find(analyzeHeaders(headers({}), "http://localhost:3000/", null), /plain HTTP/), undefined);
  });

  test("a strict policy produces no CSP or framing findings", () => {
    const f = analyzeHeaders(headers({
      "Content-Security-Policy": "default-src 'self'; script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'",
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Permissions-Policy": "camera=()"
    }), "https://shop.test/", null);
    assert.deepEqual(titles(f), []);
  });

  test("detects weak CSP directives", () => {
    const f = analyzeHeaders(headers({ "Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:" }), "https://shop.test/", null);
    assert.ok(find(f, /unsafe-inline/));
    assert.ok(find(f, /unsafe-eval/));
    assert.ok(find(f, /overly broad/));
    assert.ok(find(f, /object-src/));
  });

  test("nonces make 'unsafe-inline' harmless", () => {
    const f = analyzeHeaders(headers({ "Content-Security-Policy": "script-src 'nonce-xyz' 'unsafe-inline'; object-src 'none'; base-uri 'none'" }), "https://shop.test/", null);
    assert.equal(find(f, /unsafe-inline/), undefined);
  });

  test("short HSTS max-age is low severity", () => {
    const f = analyzeHeaders(headers({ "Strict-Transport-Security": "max-age=3600" }), "https://shop.test/", null);
    assert.equal(find(f, /HSTS max-age is short/).severity, "low");
  });

  test("CORS wildcard with credentials is high", () => {
    const f = analyzeHeaders(headers({ "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true" }), "https://api.test/", null);
    assert.equal(find(f, /wildcard origin with credentials/).severity, "high");
  });

  test("version disclosure headers are reported", () => {
    const f = analyzeHeaders(headers({ Server: "Apache/2.4.29", "X-Powered-By": "PHP/7.1" }), "https://shop.test/", null);
    assert.ok(find(f, /disclosure: server/));
    assert.ok(find(f, /disclosure: x-powered-by/));
  });

  test("session Set-Cookie without flags is flagged and the value is masked", () => {
    const f = analyzeHeaders(headers({ "Set-Cookie": "PHPSESSID=abcdef1234567890; path=/" }), "https://shop.test/", null);
    const c = find(f, /PHPSESSID/);
    assert.equal(c.severity, "medium");
    assert.match(c.title, /Secure, HttpOnly, SameSite/);
    assert.ok(!c.evidence.includes("abcdef1234567890"), "cookie value must be masked");
  });

  test("missing capture produces an info hint instead of crashing", () => {
    assert.ok(find(analyzeHeaders(null, "https://shop.test/", null), /not available/));
  });
});

describe("analyzeCookies", () => {
  const base = { domain: "shop.test", path: "/", httpOnly: true, secure: true, sameSite: "lax" };

  test("JS-readable session cookie is medium", () => {
    const f = analyzeCookies([{ ...base, name: "session_id", value: "x".repeat(26), httpOnly: false }], "https://shop.test/");
    assert.equal(f[0].severity, "medium");
    assert.match(f[0].title, /not HttpOnly/);
  });

  test("well-configured cookies produce nothing", () => {
    assert.deepEqual(analyzeCookies([{ ...base, name: "session_id", value: "abc" }], "https://shop.test/"), []);
  });

  test("non-session preference cookies are ignored", () => {
    assert.deepEqual(analyzeCookies([{ ...base, name: "theme", value: "dark", httpOnly: false, expirationDate: 1e10 }], "https://shop.test/"), []);
  });

  test("an unsigned JWT in a cookie is high", () => {
    const token = jwt({ alg: "none" }, { sub: "1" }, "");
    const f = analyzeCookies([{ ...base, name: "auth", value: token }], "https://shop.test/");
    assert.equal(find(f, /Unsigned JWT/).severity, "high");
  });
});

describe("analyzeJwt", () => {
  test("flags sensitive claims and long lifetimes", () => {
    const f = analyzeJwt(jwt({ alg: "HS256" }, { sub: "1", password: "x", iat: 0, exp: 60 * 60 * 24 * 90 }), "storage");
    assert.ok(find(f, /sensitive claims/));
    assert.ok(find(f, /Long-lived/));
  });

  test("ignores tokens that are not JSON", () => {
    assert.deepEqual(analyzeJwt("not.a.jwt", "x"), []);
  });
});

describe("scanSecrets", () => {
  const AWS = "AKIA" + "ABCDEFGHIJKLMNOP";
  const STRIPE = "sk_live_" + "a1b2c3d4e5f6g7h8i9j0k1l2";
  const GITHUB = "ghp_" + "a".repeat(36);

  test("detects provider keys and masks them in evidence", () => {
    const f = scanSecrets([{ origin: "inline <script> #1", text: `const a = "${AWS}"; const s = "${STRIPE}"; const g = "${GITHUB}";` }]);
    for (const re of [/AWS access key/, /Stripe secret key/, /GitHub token/]) {
      const hit = find(f, re);
      assert.ok(hit, `expected ${re}`);
      assert.equal(hit.severity, "high");
    }
    const evidence = f.map((x) => x.evidence).join("\n");
    for (const secret of [AWS, STRIPE, GITHUB]) assert.ok(!evidence.includes(secret), "full secret must not appear in evidence");
  });

  test("hard-coded credentials are found but placeholders are ignored", () => {
    const real = scanSecrets([{ origin: "a.js", text: `client_secret: "Zx9!qPl2#vB7"` }]);
    assert.ok(find(real, /Hard-coded credential/));
    const fake = scanSecrets([{ origin: "a.js", text: `password: "changeme123", api_key: "your_api_key_here", secret: "xxxxxxxxxx"` }]);
    assert.equal(find(fake, /Hard-coded credential/), undefined);
  });

  test("the same secret in two places is reported once with both locations", () => {
    const f = scanSecrets([{ origin: "one.js", text: AWS }, { origin: "two.js", text: AWS }]);
    const hits = f.filter((x) => /AWS/.test(x.title));
    assert.equal(hits.length, 1);
    assert.match(hits[0].evidence, /one\.js, two\.js/);
  });

  test("JWTs are reported and analysed", () => {
    const f = scanSecrets([{ origin: "localStorage", text: jwt({ alg: "none" }, { sub: "123456" }, "abcdef") }]);
    assert.ok(find(f, /JWT exposed/));
    assert.ok(find(f, /Unsigned JWT/));
  });

  test("mask keeps only the ends", () => {
    assert.equal(mask("abcdefghijklmnopqrst"), "abcdef…qrst (20 chars)");
  });
});

describe("scanCodePatterns", () => {
  test("finds a URL source flowing into innerHTML", () => {
    const f = scanCodePatterns([{ origin: "inline", code: true, text: "var q = location.hash.slice(1); el.innerHTML = q;" }]);
    assert.equal(find(f, /source→sink/).severity, "medium");
  });

  test("finds postMessage handlers without an origin check", () => {
    const f = scanCodePatterns([{ origin: "inline", code: true, text: "window.addEventListener('message', e => { run(e.data) })" }]);
    assert.ok(find(f, /without an origin check/));
    const safe = scanCodePatterns([{ origin: "inline", code: true, text: "window.addEventListener('message', e => { if (e.origin !== 'https://a.test') return; run(e.data) })" }]);
    assert.equal(find(safe, /without an origin check/), undefined);
  });

  test("skips sources that are not first-party code", () => {
    assert.deepEqual(scanCodePatterns([{ origin: "cdn.js", code: false, text: "el.innerHTML = location.hash" }]), []);
  });
});

describe("extractEndpoints", () => {
  test("finds API paths, skips static assets and ranks interesting ones first", () => {
    const eps = extractEndpoints([{ origin: "app.js", text: `fetch("/api/v1/users"); img = "/static/logo.png"; x = "/about"; y = "https://cdn.test/lib.js"` }], "https://shop.test/");
    const urls = eps.map((e) => e.url);
    assert.ok(urls.includes("/api/v1/users"));
    assert.ok(!urls.includes("/static/logo.png"));
    assert.equal(eps[0].url, "/api/v1/users");
    assert.equal(eps.find((e) => e.url === "https://cdn.test/lib.js").external, true);
  });
});

describe("libraries", () => {
  test("compareVersions orders semantic versions numerically", () => {
    assert.ok(compareVersions("1.12.4", "3.5.0") < 0);
    assert.ok(compareVersions("3.10.0", "3.5.0") > 0);
    assert.equal(compareVersions("2.0", "2.0.0"), 0);
  });

  test("flags old jQuery and Bootstrap but not current versions", () => {
    const f = analyzeLibraries([
      { name: "jQuery", version: "1.12.4", how: "x" },
      { name: "jQuery", version: "3.7.1", how: "x" },
      { name: "Bootstrap", version: "4.2.1", how: "x" },
      { name: "Bootstrap", version: "5.3.0", how: "x" },
      { name: "React", version: null, how: "x" }
    ]);
    assert.deepEqual(titles(f).sort(), ["Bootstrap 4.2.1 has known vulnerabilities", "jQuery 1.12.4 has known vulnerabilities"]);
  });
});

describe("analyzeConsole", () => {
  test("groups CSP violations and errors, and flags logged credentials", () => {
    const f = analyzeConsole([
      { level: "csp-violation", text: "'script-src' blocked https://evil.test/x.js" },
      { level: "error", text: "TypeError: x is undefined" },
      { level: "log", text: "auth token = abc" }
    ]);
    assert.ok(find(f, /CSP violation/));
    assert.ok(find(f, /JavaScript error/));
    assert.equal(find(f, /mention credentials/).severity, "low");
  });
});

describe("ACTIVE_PROBES validators", () => {
  const probe = (path) => ACTIVE_PROBES.find((p) => p.path === path);

  test(".git/HEAD only matches real git refs", () => {
    assert.equal(probe("/.git/HEAD").test("ref: refs/heads/main\n"), true);
    assert.equal(probe("/.git/HEAD").test("<!doctype html><title>404</title>"), false);
  });

  test(".env only matches KEY=value files, not HTML", () => {
    assert.equal(probe("/.env").test("DB_PASSWORD=hunter2\nAPP_KEY=x"), true);
    assert.equal(probe("/.env").test("<html>DB_PASSWORD=x</html>"), false);
  });

  test("robots.txt evidence lists disallowed paths", () => {
    const p = probe("/robots.txt");
    const text = "User-agent: *\nDisallow: /admin\nDisallow: /internal/";
    assert.equal(p.test(text), true);
    assert.equal(p.evidence(text), "Disallow: /admin\nDisallow: /internal/");
  });
});
