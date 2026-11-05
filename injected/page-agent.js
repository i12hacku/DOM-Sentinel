// Injected on demand into the ISOLATED world. Defines globalThis.__DTA_AGENT__,
// which the background calls via chrome.scripting.executeScript.
// Every method catches its own errors and returns plain JSON.
(() => {
  if (globalThis.__DTA_AGENT__) return;

  const MAX_SOURCE_TOTAL = 1_500_000;
  const MAX_HIDDEN = 400;
  const MAX_WALK = 12000;

  const STRONG_WORDS = /\b(admin(istrator)?|debug|secret|passw(or)?d|token|api[_-]?key|internal|backdoor|superuser|root|staging|private|credential)s?\b/i;
  const WEAK_WORDS = /\b(test(ing)?|dev(elopment)?|beta|hidden|todo|fixme|hack|role|is_?admin|price|discount|coupon|flag|config|feature)\b/i;
  const UI_WIDGET = /(modal|dropdown|menu|tooltip|popover|toast|dialog|carousel|collapse|tab-pane|offcanvas|accordion|submenu|nav)/i;
  const SKIP_TAGS = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE", "HEAD", "META", "LINK", "BR", "WBR", "svg", "SVG", "PATH", "DEFS"]);
  const RISKY_HIDDEN_FIELD = /(role|admin|price|amount|total|cost|discount|user_?id|uid|account|permission|level|^is_|debug|redirect|return|next|url|callback|email|plan|tier|quantity)/i;

  const state = {
    hiddenEls: [],
    revealed: new Map(),
    pickerCleanup: null
  };

  const clip = (s, n = 300) => {
    s = String(s ?? "");
    return s.length > n ? s.slice(0, n) + "…" : s;
  };

  function cssPath(el) {
    if (!(el instanceof Element)) return "";
    const uniqueId = (e) => e.id && document.querySelectorAll("#" + CSS.escape(e.id)).length === 1;
    if (uniqueId(el)) return "#" + CSS.escape(el.id);
    const parts = [];
    let cur = el;
    while (cur && cur.nodeType === 1 && cur !== document.documentElement && parts.length < 10) {
      if (uniqueId(cur)) { parts.unshift("#" + CSS.escape(cur.id)); break; }
      let part = cur.localName;
      const parent = cur.parentElement;
      if (parent) {
        const same = Array.from(parent.children).filter((c) => c.localName === cur.localName);
        if (same.length > 1) part += `:nth-of-type(${same.indexOf(cur) + 1})`;
      }
      parts.unshift(part);
      cur = parent;
    }
    return parts.join(" > ");
  }

  function hiddenReason(el, cs) {
    if (el.hidden) return "hidden attribute";
    if (cs.display === "none") return "display:none";
    if (cs.visibility === "hidden" || cs.visibility === "collapse") return "visibility:" + cs.visibility;
    if (parseFloat(cs.opacity) < 0.05) return "opacity:" + cs.opacity;
    const r = el.getBoundingClientRect();
    const hasContent = el.childElementCount > 0 || (el.textContent || "").trim().length > 0;
    if (hasContent && (cs.position === "absolute" || cs.position === "fixed")) {
      const left = r.left + scrollX, top = r.top + scrollY;
      if (r.right + scrollX < -20 || r.bottom + scrollY < -20 || left > document.documentElement.scrollWidth + 500 || top > document.documentElement.scrollHeight + 2000) {
        return "positioned off-screen";
      }
    }
    if (hasContent && (cs.clip === "rect(0px, 0px, 0px, 0px)" || /inset\(\s*(50|100)%/.test(cs.clipPath))) return "clipped (visually hidden)";
    if (hasContent && r.width <= 1 && r.height <= 1 && cs.overflow === "hidden") return "zero size + overflow:hidden";
    if (parseFloat(cs.textIndent) < -999) return "text-indent off-screen";
    if (hasContent && el.childElementCount === 0 && parseFloat(cs.fontSize) === 0) return "font-size:0";
    return null;
  }

  function describeContents(el) {
    return {
      inputs: el.querySelectorAll("input:not([type=hidden]), textarea, select").length,
      buttons: el.querySelectorAll("button, input[type=submit], input[type=button]").length,
      links: el.querySelectorAll("a[href]").length + (el.matches("a[href]") ? 1 : 0),
      forms: el.querySelectorAll("form").length + (el.matches("form") ? 1 : 0),
      iframes: el.querySelectorAll("iframe").length
    };
  }

  function scanHidden(findings) {
    state.hiddenEls = [];
    const items = [];
    let visited = 0;
    let total = 0;
    if (!document.body) return items;

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT, {
      acceptNode(node) {
        if (++visited > MAX_WALK) return NodeFilter.FILTER_REJECT;
        if (SKIP_TAGS.has(node.tagName) || node.closest("svg")) return NodeFilter.FILTER_REJECT;
        if (node.matches("input[type=hidden]")) return NodeFilter.FILTER_REJECT;
        const cs = getComputedStyle(node);
        const reason = hiddenReason(node, cs);
        if (!reason) return NodeFilter.FILTER_SKIP; // keep walking children
        total += 1;
        const text = (node.textContent || "").replace(/\s+/g, " ").trim();
        const attrText = [node.id, node.className && String(node.className), node.getAttribute("name"), node.getAttribute("href"), node.getAttribute("aria-label")].filter(Boolean).join(" ");
        const contents = describeContents(node);
        const why = [];
        const strong = STRONG_WORDS.exec(text.slice(0, 2000) + " " + attrText);
        const weak = !strong && WEAK_WORDS.exec(text.slice(0, 2000) + " " + attrText);
        if (strong) why.push(`keyword "${strong[0]}"`);
        if (weak) why.push(`keyword "${weak[0]}"`);
        if (contents.forms) why.push(`${contents.forms} form(s)`);
        if (contents.inputs) why.push(`${contents.inputs} input(s)`);
        if (contents.buttons) why.push(`${contents.buttons} button(s)`);
        if (contents.links) why.push(`${contents.links} link(s)`);
        if (contents.iframes) why.push(`${contents.iframes} iframe(s)`);
        const isWidget = UI_WIDGET.test(attrText) || reason.startsWith("clipped") || node.getAttribute("role") === "dialog";
        const interesting = Boolean(strong) || (!isWidget && (contents.forms + contents.inputs + contents.iframes > 0 || Boolean(weak)));

        if (items.length < MAX_HIDDEN) {
          const ref = state.hiddenEls.push(node) - 1;
          items.push({
            ref,
            selector: cssPath(node),
            tag: node.localName,
            reason,
            interesting,
            why,
            isWidget,
            text: clip(text, 200),
            html: clip(node.outerHTML, 500)
          });
          if (interesting) {
            findings.push({
              category: "Hidden elements",
              severity: strong && (contents.inputs + contents.buttons + contents.links + contents.forms) > 0 ? "medium" : "low",
              title: `Hidden <${node.localName}> containing ${why.join(", ") || "content"}`,
              description: `Element is hidden via ${reason}. Hidden UI is often unfinished, admin-only, or feature-flagged functionality. Hiding it client-side does not protect the backend endpoint behind it.`,
              evidence: clip(node.outerHTML, 800),
              selector: cssPath(node),
              recommendation: "Reveal it (Hidden tab → Reveal all) and test whether the actions it exposes are authorized server-side. Remove dead/admin markup from production responses."
            });
          }
        }
        return NodeFilter.FILTER_REJECT; // children are hidden too; don't double-report
      }
    });
    while (walker.nextNode()) { /* acceptNode does the work */ }
    return { items, total };
  }

  function scanHiddenInputs(findings, sources) {
    const inputs = Array.from(document.querySelectorAll("input[type=hidden]"));
    const plain = [];
    for (const input of inputs) {
      const name = input.name || input.id || "(unnamed)";
      const value = input.value || "";
      if (value.length > 8) sources.push({ origin: `hidden input "${name}"`, text: value.slice(0, 5000) });
      if (RISKY_HIDDEN_FIELD.test(name)) {
        findings.push({
          category: "Hidden elements",
          severity: "low",
          title: `Client-controlled hidden field "${name}"`,
          description: "Hidden form fields are fully editable by the user. If the server trusts this value (price, role, user id, redirect target…) it can be tampered with.",
          evidence: clip(input.outerHTML, 400),
          selector: cssPath(input),
          recommendation: "Change the value in the Inspector tab, submit the form and confirm the server re-validates it. Never trust security-relevant values from the client."
        });
      } else {
        plain.push(`${name} = ${clip(value, 60)}`);
      }
    }
    if (plain.length) {
      findings.push({
        category: "Hidden elements",
        severity: "info",
        title: `${plain.length} other hidden input(s)`,
        description: "Hidden inputs found on the page. Review for anything the server should not be trusting.",
        evidence: plain.slice(0, 40).join("\n"),
        recommendation: "Review whether any of these influence authorization or pricing."
      });
    }
  }

  function scanDisabled(findings) {
    const els = Array.from(document.querySelectorAll("button[disabled], input[disabled], select[disabled], textarea[disabled], [readonly], [aria-disabled=true]")).slice(0, 60);
    if (!els.length) return;
    const lines = els.map((e) => `${cssPath(e)}  ${clip((e.textContent || e.value || e.name || "").trim(), 50)}`);
    findings.push({
      category: "Hidden elements",
      severity: "info",
      title: `${els.length} disabled / read-only control(s)`,
      description: "Disabled or read-only controls are a client-side restriction only. Re-enabling them (Console → snippet \"Enable disabled controls\") lets you test whether the server enforces the same rule.",
      evidence: lines.join("\n"),
      recommendation: "Enforce the same restriction on the server."
    });
  }

  function scanComments(findings, sources) {
    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
    const hits = [];
    let n = 0;
    while (walker.nextNode() && n < 3000) {
      n += 1;
      const text = walker.currentNode.nodeValue.trim();
      if (!text || /^\[if |^\[endif|^ko |^\/ko|^\$|^\/\$|^react-|^-->$/.test(text)) continue;
      sources.push({ origin: "HTML comment", text: text.slice(0, 5000) });
      if (STRONG_WORDS.test(text) || WEAK_WORDS.test(text) || /(https?:\/\/|\/[a-z0-9_-]+\/[a-z0-9_-]+|<[a-z]+[\s>])/i.test(text)) {
        hits.push(clip(text.replace(/\s+/g, " "), 240));
      }
    }
    if (hits.length) {
      findings.push({
        category: "Information disclosure",
        severity: hits.some((h) => STRONG_WORDS.test(h)) ? "low" : "info",
        title: `${hits.length} HTML comment(s) with interesting content`,
        description: "HTML comments are shipped to every visitor. They often leak internal paths, commented-out features, TODOs or credentials.",
        evidence: hits.slice(0, 30).map((h) => "<!-- " + h + " -->").join("\n"),
        recommendation: "Strip comments from production HTML (most build tools can do this)."
      });
    }
  }

  function scanForms(findings) {
    const isHttps = location.protocol === "https:";
    for (const form of Array.from(document.forms).slice(0, 80)) {
      const sel = cssPath(form);
      const method = (form.getAttribute("method") || "GET").toUpperCase();
      const actionAttr = form.getAttribute("action");
      let action;
      try { action = new URL(actionAttr || location.href, location.href); } catch (_) { continue; }
      const hasPassword = Boolean(form.querySelector("input[type=password]"));
      const tokenField = form.querySelector("input[name*=csrf i], input[name*=xsrf i], input[name*=token i], input[name*=authenticity i], input[name*=nonce i], input[name=__RequestVerificationToken]");
      const snippet = clip(form.outerHTML, 600);

      if (hasPassword && (!isHttps || action.protocol === "http:")) {
        findings.push({ category: "Forms", severity: "high", title: "Password form submitted over plain HTTP", description: "Credentials can be read or modified by anyone on the network path.", evidence: `action=${action.href}\n${snippet}`, selector: sel, recommendation: "Serve the page and the form action over HTTPS only, and enable HSTS." });
      }
      if (hasPassword && method === "GET") {
        findings.push({ category: "Forms", severity: "medium", title: "Password form uses GET", description: "Credentials will appear in the URL, browser history, proxy logs and Referer headers.", evidence: snippet, selector: sel, recommendation: "Use method=\"POST\"." });
      }
      if (method === "POST" && !tokenField) {
        findings.push({ category: "Forms", severity: "low", title: "POST form without a visible anti-CSRF token", description: "No hidden token field was found. The app may rely on SameSite cookies or a header token instead — verify.", evidence: snippet, selector: sel, recommendation: "Confirm CSRF protection: submit the request from another origin (or remove the cookie's SameSite) and see if it is accepted." });
      }
      if (actionAttr && action.origin !== location.origin && /^https?:$/.test(action.protocol)) {
        findings.push({ category: "Forms", severity: hasPassword ? "medium" : "info", title: `Form posts to another origin (${action.host})`, description: "Data entered in this form is sent to a third-party origin.", evidence: snippet, selector: sel, recommendation: "Confirm the destination is expected and trusted." });
      }
    }
    const loosePw = Array.from(document.querySelectorAll("input[type=password]")).filter((i) => !i.form);
    if (loosePw.length && location.protocol !== "https:") {
      findings.push({ category: "Forms", severity: "high", title: "Password field on a non-HTTPS page", description: "Credentials are typed into a page that is not protected by TLS.", evidence: clip(loosePw[0].outerHTML, 300), selector: cssPath(loosePw[0]), recommendation: "Serve the page over HTTPS." });
    }
  }

  function scanLinksAndHandlers(findings) {
    const all = Array.from(document.querySelectorAll("*")).slice(0, 15000);
    const handlerSamples = [];
    let handlerCount = 0;
    const jsUrls = [];
    for (const el of all) {
      for (const attr of el.attributes) {
        const name = attr.name.toLowerCase();
        if (name.startsWith("on") && name.length > 3) {
          handlerCount += 1;
          if (handlerSamples.length < 15) handlerSamples.push(`${cssPath(el)}  ${name}="${clip(attr.value, 100)}"`);
        } else if ((name === "href" || name === "src" || name === "action" || name === "formaction") && /^\s*javascript:/i.test(attr.value)) {
          if (attr.value.replace(/\s/g, "").toLowerCase() !== "javascript:void(0)" && attr.value.replace(/\s/g, "").toLowerCase() !== "javascript:;") {
            jsUrls.push(`${cssPath(el)}  ${name}="${clip(attr.value, 120)}"`);
          }
        }
      }
    }
    if (handlerCount) {
      findings.push({ category: "DOM XSS hints", severity: "info", title: `${handlerCount} inline event handler attribute(s)`, description: "Inline handlers (onclick=…) force CSP to allow 'unsafe-inline' or 'unsafe-hashes', weakening XSS protection.", evidence: handlerSamples.join("\n"), recommendation: "Move handlers to addEventListener in external scripts." });
    }
    if (jsUrls.length) {
      findings.push({ category: "DOM XSS hints", severity: "low", title: `${jsUrls.length} javascript: URL(s)`, description: "javascript: URLs execute code on navigation and are blocked by strict CSP. If any part is user-controlled it is an XSS vector.", evidence: jsUrls.slice(0, 20).join("\n"), recommendation: "Replace with event listeners." });
    }

    const blankLinks = Array.from(document.querySelectorAll("a[target=_blank][href]")).filter((a) => {
      try { return new URL(a.href).origin !== location.origin && !/noopener|noreferrer/i.test(a.rel); } catch (_) { return false; }
    });
    if (blankLinks.length) {
      findings.push({ category: "Links", severity: "info", title: `${blankLinks.length} cross-origin target=_blank link(s) without rel="noopener"`, description: "Modern browsers imply noopener, but older ones allow the opened page to navigate this tab (reverse tabnabbing).", evidence: blankLinks.slice(0, 15).map((a) => a.href).join("\n"), recommendation: "Add rel=\"noopener noreferrer\"." });
    }
  }

  function scanResources(findings) {
    const isHttps = location.protocol === "https:";
    if (isHttps) {
      const mixed = Array.from(document.querySelectorAll("script[src^='http:'], iframe[src^='http:'], link[rel~=stylesheet][href^='http:'], img[src^='http:'], video[src^='http:'], audio[src^='http:'], source[src^='http:'], object[data^='http:'], embed[src^='http:'], form[action^='http:']"));
      if (mixed.length) {
        const active = mixed.filter((e) => /^(script|iframe|link|object|embed|form)$/.test(e.localName));
        findings.push({ category: "Transport", severity: active.length ? "medium" : "low", title: `${mixed.length} mixed-content reference(s) on an HTTPS page`, description: active.length ? "Active content (scripts/frames/styles/forms) loaded over HTTP can be modified in transit." : "Passive content loaded over HTTP leaks requests and can be swapped.", evidence: mixed.slice(0, 20).map((e) => clip(e.outerHTML, 160)).join("\n"), selector: cssPath(mixed[0]), recommendation: "Load all resources over HTTPS; consider CSP upgrade-insecure-requests." });
      }
    }

    const noSri = Array.from(document.querySelectorAll("script[src], link[rel~=stylesheet][href]")).filter((e) => {
      try { return new URL(e.src || e.href).origin !== location.origin && !e.integrity; } catch (_) { return false; }
    });
    if (noSri.length) {
      findings.push({ category: "Third-party code", severity: "low", title: `${noSri.length} third-party script/style(s) without Subresource Integrity`, description: "If the third-party host is compromised, it can run arbitrary code on this page.", evidence: noSri.slice(0, 25).map((e) => e.src || e.href).join("\n"), recommendation: "Add integrity=\"sha384-…\" crossorigin=\"anonymous\" for static CDN assets, or self-host them." });
    }

    const frames = Array.from(document.querySelectorAll("iframe")).filter((f) => {
      try { return f.src && new URL(f.src).origin !== location.origin && !f.hasAttribute("sandbox"); } catch (_) { return false; }
    });
    if (frames.length) {
      findings.push({ category: "Third-party code", severity: "info", title: `${frames.length} cross-origin iframe(s) without sandbox`, description: "Unsandboxed frames can run scripts, open popups and navigate the top window (if allowed).", evidence: frames.slice(0, 15).map((f) => f.src).join("\n"), selector: cssPath(frames[0]), recommendation: "Add a sandbox attribute with only the permissions needed." });
    }
  }

  function scanReflection(findings) {
    const params = [];
    const url = new URL(location.href);
    url.searchParams.forEach((v, k) => params.push({ k, v, where: "query" }));
    const hash = decodeURIComponent(location.hash.slice(1) || "");
    if (hash.includes("=")) new URLSearchParams(hash.replace(/^[!/]*/, "")).forEach((v, k) => params.push({ k, v, where: "hash" }));
    else if (hash.length >= 4) params.push({ k: "#", v: hash, where: "hash" });

    if (!params.length) return;
    const html = document.documentElement.outerHTML;
    for (const { k, v, where } of params.slice(0, 40)) {
      if (!v || v.length < 4 || /^\d+$/.test(v) || /^(true|false|null)$/i.test(v)) continue;
      const idx = html.indexOf(v);
      if (idx < 0) continue;
      const before = html.slice(0, idx);
      const inTag = before.lastIndexOf("<") > before.lastIndexOf(">");
      const inScript = before.lastIndexOf("<script") > before.lastIndexOf("</script");
      const dangerousChars = /[<>"'`]/.test(v);
      const context = inScript ? "inside a <script> block" : inTag ? "inside an HTML tag/attribute" : "in page text";
      findings.push({
        category: "DOM XSS hints",
        severity: dangerousChars ? "high" : inScript || inTag ? "medium" : "low",
        title: `${where} parameter "${k}" is reflected ${context}`,
        description: dangerousChars
          ? "The parameter value contains HTML/JS metacharacters and appears unescaped in the DOM — likely XSS."
          : "User-controlled input is reflected into the page. Test whether special characters are encoded correctly for this context.",
        evidence: "…" + html.slice(Math.max(0, idx - 120), idx + v.length + 120) + "…",
        recommendation: `Retry with a harmless marker like ${k}=dta"'<b>x</b> and inspect how it is rendered. Encode output for the exact context (HTML, attribute, JS string, URL).`
      });
    }
  }

  function scanStorage(findings, sources) {
    const out = { localStorage: [], sessionStorage: [] };
    for (const area of ["localStorage", "sessionStorage"]) {
      let store;
      try { store = window[area]; } catch (_) { continue; }
      if (!store) continue;
      for (let i = 0; i < Math.min(store.length, 200); i++) {
        const key = store.key(i);
        const value = store.getItem(key) || "";
        out[area].push({ key, size: value.length, preview: clip(value, 120) });
        sources.push({ origin: `${area}["${key}"]`, text: value.slice(0, 20000) });
        const sensitiveKey = /(token|jwt|auth|session|bearer|access|refresh|secret|passw|api[_-]?key|credential)/i.test(key);
        const jwt = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\./.test(value);
        if (sensitiveKey || jwt) {
          findings.push({ category: "Storage", severity: "medium", title: `Possible auth token in ${area} ("${key}")`, description: "Web Storage is readable by any script on the origin, so a single XSS can steal it. HttpOnly cookies are not readable by JavaScript.", evidence: `${key} = ${clip(value, 80)}`, recommendation: "Prefer HttpOnly + Secure + SameSite cookies for session tokens, and keep tokens short-lived." });
        }
      }
    }
    return out;
  }

  function collectSources(sources) {
    let i = 0;
    for (const s of document.scripts) {
      i += 1;
      if (!s.src && s.textContent.trim()) sources.push({ origin: `inline <script> #${i}${s.type ? " (" + s.type + ")" : ""}`, text: s.textContent, inline: true });
    }
    for (const m of document.querySelectorAll("meta[content]")) {
      const c = m.getAttribute("content");
      if (c.length > 15) sources.push({ origin: `<meta ${m.getAttribute("name") || m.getAttribute("property") || m.getAttribute("http-equiv") || ""}>`, text: c });
    }
    for (const el of document.querySelectorAll("*")) {
      for (const a of el.attributes) {
        if (a.name.startsWith("data-") && a.value.length > 20) sources.push({ origin: `${a.name} on ${cssPath(el)}`, text: a.value.slice(0, 10000) });
      }
    }
    // Enforce total size budget
    let total = 0;
    const kept = [];
    for (const s of sources) {
      if (total > MAX_SOURCE_TOTAL) break;
      const text = s.text.slice(0, MAX_SOURCE_TOTAL - total);
      total += text.length;
      kept.push({ ...s, text });
    }
    return kept;
  }

  // ---------- public methods ----------

  async function collect() {
    const findings = [];
    const sources = [];
    const started = performance.now();
    const hidden = scanHidden(findings);
    scanHiddenInputs(findings, sources);
    scanDisabled(findings);
    scanComments(findings, sources);
    scanForms(findings);
    scanLinksAndHandlers(findings);
    scanResources(findings);
    scanReflection(findings);
    const storage = scanStorage(findings, sources);
    const cspMeta = document.querySelector("meta[http-equiv='Content-Security-Policy' i]");

    return {
      ok: true,
      url: location.href,
      title: document.title,
      findings,
      hidden: hidden.items || [],
      hiddenTotal: hidden.total || 0,
      storage,
      scriptUrls: Array.from(document.scripts).filter((s) => s.src).map((s) => s.src).slice(0, 200),
      jsCookieNames: document.cookie ? document.cookie.split(";").map((c) => c.split("=")[0].trim()).filter(Boolean) : [],
      cspMeta: cspMeta ? cspMeta.getAttribute("content") : null,
      sources: collectSources(sources),
      stats: {
        elements: document.getElementsByTagName("*").length,
        forms: document.forms.length,
        scripts: document.scripts.length,
        iframes: document.querySelectorAll("iframe").length,
        ms: Math.round(performance.now() - started)
      }
    };
  }

  async function fetchHeaders() {
    try {
      const res = await fetch(location.href, { credentials: "include", cache: "no-store" });
      return { ok: true, url: res.url, statusCode: res.status, headers: Array.from(res.headers.entries()).map(([name, value]) => ({ name, value })), via: "page fetch (Set-Cookie not visible)" };
    } catch (e) {
      return { ok: false, error: String(e) };
    }
  }

  function overlayHost() {
    let host = document.getElementById("__dta_overlay_host");
    if (!host) {
      host = document.createElement("div");
      host.id = "__dta_overlay_host";
      host.style.cssText = "position:fixed;inset:0;pointer-events:none;z-index:2147483647;";
      host.attachShadow({ mode: "open" });
      document.documentElement.appendChild(host);
    }
    return host.shadowRoot;
  }

  function drawBox(root, el, label, color = "#ff2d95") {
    const r = el.getBoundingClientRect();
    const box = document.createElement("div");
    box.style.cssText = `position:fixed;left:${r.left}px;top:${r.top}px;width:${Math.max(r.width, 4)}px;height:${Math.max(r.height, 4)}px;border:2px solid ${color};background:${color}22;box-sizing:border-box;transition:opacity .3s;`;
    const tag = document.createElement("div");
    tag.textContent = label;
    tag.style.cssText = `position:absolute;left:-2px;top:-20px;background:${color};color:#fff;font:11px/18px monospace;padding:0 6px;white-space:nowrap;max-width:60vw;overflow:hidden;text-overflow:ellipsis;`;
    box.appendChild(tag);
    root.appendChild(box);
    return box;
  }

  function resolve(selector, ref) {
    if (typeof ref === "number" && state.hiddenEls[ref]?.isConnected) return state.hiddenEls[ref];
    if (!selector) return null;
    try { return document.querySelector(selector); } catch (_) { return null; }
  }

  function highlight(selector, ref) {
    const el = resolve(selector, ref);
    if (!el) return { ok: false, error: "Element not found (the page may have changed — rescan)." };
    const reason = hiddenReason(el, getComputedStyle(el));
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    setTimeout(() => {
      const box = drawBox(overlayHost(), el, `${cssPath(el)}${reason ? "  [hidden: " + reason + "]" : ""}`);
      setTimeout(() => { box.style.opacity = "0"; setTimeout(() => box.remove(), 400); }, 3500);
    }, 350);
    return { ok: true, hidden: reason };
  }

  function revealOne(el) {
    if (state.revealed.has(el)) return;
    state.revealed.set(el, { style: el.getAttribute("style"), hidden: el.hasAttribute("hidden") });
    el.removeAttribute("hidden");
    const cs = getComputedStyle(el);
    if (cs.display === "none") el.style.setProperty("display", el.localName === "span" || el.localName === "a" ? "inline-block" : "block", "important");
    el.style.setProperty("visibility", "visible", "important");
    el.style.setProperty("opacity", "1", "important");
    if (cs.position === "absolute" || cs.position === "fixed") {
      const r = el.getBoundingClientRect();
      if (r.right < 0 || r.bottom < 0 || r.left > innerWidth * 3) el.style.setProperty("position", "static", "important");
    }
    if (parseFloat(cs.textIndent) < -999) el.style.setProperty("text-indent", "0", "important");
    if (cs.clip !== "auto") el.style.setProperty("clip", "auto", "important");
    if (cs.clipPath !== "none") el.style.setProperty("clip-path", "none", "important");
    el.style.setProperty("outline", "2px dashed #ff2d95", "important");
    el.style.setProperty("outline-offset", "2px", "important");
    el.setAttribute("data-dta-revealed", "1");
  }

  function revealHidden(on, onlyInteresting, ref) {
    if (on) {
      const targets = typeof ref === "number" ? [state.hiddenEls[ref]] : state.hiddenEls;
      let n = 0;
      targets.forEach((el, i) => {
        if (!el || !el.isConnected) return;
        if (onlyInteresting && typeof ref !== "number" && !state.lastInteresting?.has(i)) return;
        revealOne(el);
        n += 1;
      });
      return { ok: true, revealed: n };
    }
    let n = 0;
    for (const [el, orig] of state.revealed) {
      if (orig.style === null) el.removeAttribute("style"); else el.setAttribute("style", orig.style);
      if (orig.hidden) el.setAttribute("hidden", "");
      el.removeAttribute("data-dta-revealed");
      n += 1;
    }
    state.revealed.clear();
    return { ok: true, restored: n };
  }

  function readElement(selector) {
    const el = resolve(selector);
    if (!el) return { ok: false, error: `No element matches: ${selector}` };
    const cs = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    return {
      ok: true,
      selector: cssPath(el),
      tag: el.localName,
      hiddenReason: hiddenReason(el, cs),
      attributes: Object.fromEntries(Array.from(el.attributes).map((a) => [a.name, clip(a.value, 500)])),
      box: { x: Math.round(r.left), y: Math.round(r.top), width: Math.round(r.width), height: Math.round(r.height) },
      computed: { display: cs.display, visibility: cs.visibility, opacity: cs.opacity, position: cs.position, zIndex: cs.zIndex, pointerEvents: cs.pointerEvents },
      value: "value" in el ? clip(el.value, 500) : undefined,
      form: el.form ? { selector: cssPath(el.form), action: el.form.action, method: el.form.method } : undefined,
      text: clip((el.textContent || "").trim(), 800),
      outerHTML: clip(el.outerHTML, 2500),
      children: el.childElementCount
    };
  }

  function writeElement({ selector, operation, value, attributeName }) {
    const el = resolve(selector);
    if (!el) return { ok: false, error: `No element matches: ${selector}` };
    const v = String(value ?? "");
    switch (operation) {
      case "text": el.textContent = v; break;
      case "html": el.innerHTML = v; break;
      case "value": el.value = v; el.dispatchEvent(new Event("input", { bubbles: true })); el.dispatchEvent(new Event("change", { bubbles: true })); break;
      case "attribute":
        if (!attributeName) return { ok: false, error: "Attribute name required." };
        el.setAttribute(attributeName, v); break;
      case "remove-attribute":
        if (!attributeName) return { ok: false, error: "Attribute name required." };
        el.removeAttribute(attributeName); break;
      case "enable": el.disabled = false; el.removeAttribute("disabled"); el.removeAttribute("readonly"); el.removeAttribute("aria-disabled"); break;
      case "show": revealOne(el); break;
      case "style":
        for (const decl of v.split(";")) {
          const i = decl.indexOf(":");
          if (i > 0) el.style.setProperty(decl.slice(0, i).trim(), decl.slice(i + 1).trim().replace(/!important$/, "").trim(), /!important$/.test(decl.trim()) ? "important" : "");
        }
        break;
      case "remove": el.remove(); return { ok: true, removed: true };
      default: return { ok: false, error: "Unknown operation " + operation };
    }
    return { ok: true, outerHTML: clip(el.outerHTML, 2500) };
  }

  function startPicker() {
    if (state.pickerCleanup) state.pickerCleanup();
    const root = overlayHost();
    let box = null;
    let current = null;
    const move = (e) => {
      const el = document.elementFromPoint(e.clientX, e.clientY);
      if (!el || el === current || el.id === "__dta_overlay_host") return;
      current = el;
      box?.remove();
      box = drawBox(root, el, cssPath(el), "#1e90ff");
    };
    const click = (e) => {
      e.preventDefault();
      e.stopImmediatePropagation();
      const sel = cssPath(current || e.target);
      cleanup();
      chrome.runtime.sendMessage({ type: "DTA_PICKED", selector: sel }).catch(() => {});
    };
    const key = (e) => { if (e.key === "Escape") cleanup(); };
    const block = (e) => { e.preventDefault(); e.stopImmediatePropagation(); };
    function cleanup() {
      removeEventListener("mousemove", move, true);
      removeEventListener("click", click, true);
      removeEventListener("mousedown", block, true);
      removeEventListener("mouseup", block, true);
      removeEventListener("keydown", key, true);
      box?.remove();
      state.pickerCleanup = null;
    }
    addEventListener("mousemove", move, true);
    addEventListener("click", click, true);
    addEventListener("mousedown", block, true);
    addEventListener("mouseup", block, true);
    addEventListener("keydown", key, true);
    state.pickerCleanup = cleanup;
    return { ok: true };
  }

  const wrap = (fn) => async (...args) => {
    try { return await fn(...args); } catch (e) { return { ok: false, error: String(e?.stack || e) }; }
  };

  globalThis.__DTA_AGENT__ = {
    collect: wrap(async (...a) => {
      const res = await collect(...a);
      state.lastInteresting = new Set(res.hidden.filter((h) => h.interesting).map((h) => h.ref));
      return res;
    }),
    fetchHeaders: wrap(fetchHeaders),
    highlight: wrap(highlight),
    revealHidden: wrap(revealHidden),
    readElement: wrap(readElement),
    writeElement: wrap(writeElement),
    startPicker: wrap(startPicker)
  };
})();
