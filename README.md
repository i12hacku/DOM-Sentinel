<div align="center">

# ⛨ DOM Sentinel

**A Chrome DevTools extension for client-side web security analysis.**

Find leaked secrets, hidden functionality, weak security headers, insecure cookies and DOM-XSS hints on any page, right inside DevTools.

![Manifest V3](https://img.shields.io/badge/Manifest-V3-4285F4?logo=googlechrome&logoColor=white)
![Chrome 116+](https://img.shields.io/badge/Chrome-116%2B-brightgreen)
![No build step](https://img.shields.io/badge/build-none-lightgrey)
![AI optional](https://img.shields.io/badge/AI-optional%20(Gemini)-8E75B2)

</div>

---

## Overview

DOM Sentinel is a Manifest V3 browser extension for **developers, QA engineers and security testers**. It runs a local rule-based scan of the active tab. It looks at the DOM, response headers, cookies, Web Storage, inline and external JavaScript, and console output. It then shows the findings with severity levels, evidence and fix advice.

It runs in two places:

- **Side panel:** stays open while you browse.
- **DevTools → "Security" tab:** full DevTools integration (`$0`, `inspect()`, `getEventListeners()`), plus a **Security** sidebar in the Elements panel.

The scanner is **fully local and deterministic**. AI is an optional extra: it can explain and prioritise findings or write custom DevTools scripts, using your own Google Gemini API key.

> ⚠️ **Use only on applications you own or are explicitly authorised to test.**

## Features

### 🔍 Security scanner
| Area | Checks |
| --- | --- |
| **Security headers** | CSP quality (`unsafe-inline`, `unsafe-eval`, wildcards, missing `object-src` / `base-uri`), HSTS, clickjacking protection, `nosniff`, Referrer-Policy, Permissions-Policy, server/version disclosure, CORS misconfiguration |
| **Cookies** | Missing `HttpOnly` / `Secure` / `SameSite` on session cookies (including HttpOnly ones, via `chrome.cookies`) |
| **Secrets & tokens** | AWS, Google, GitHub, Slack, Stripe, OpenAI, Anthropic, SendGrid, Twilio and Mailgun keys, private keys, credentials in URLs, hard-coded passwords. JWT analysis (`alg=none`, sensitive claims, lifetime) |
| **DOM XSS hints** | Reflected URL parameters (with context detection), source→sink flows, `postMessage` handlers without an origin check, inline event handlers, `javascript:` URLs |
| **Forms** | Password forms over HTTP, credentials sent via GET, missing CSRF tokens, cross-origin form actions |
| **Information disclosure** | Sensitive HTML comments, exposed source maps, suspicious `window.*` globals, credentials in console output |
| **Third-party code** | Scripts without Subresource Integrity, unsandboxed iframes, mixed content |
| **Vulnerable libraries** | jQuery, AngularJS, lodash, moment, Bootstrap, Handlebars, DOMPurify, Prototype |
| **Active checks** *(opt-in)* | `/.git/HEAD`, `/.env`, `/.DS_Store`, `/server-status`, `phpinfo.php`, Swagger/OpenAPI specs, WordPress user enumeration, `crossdomain.xml`, `robots.txt`, `security.txt`. Includes soft-404 detection |

### 👁 Hidden element discovery
- Finds elements hidden by `display:none`, `visibility`, `opacity`, the `hidden` attribute, off-screen positioning, clipping, zero size or `text-indent`.
- Ranks them by interest: hidden forms, inputs, links, and keywords like *admin*, *debug* or *internal*.
- **Reveal / restore** them on the live page, and flag tamperable hidden inputs (`role`, `price`, `user_id`…).

### 🧭 Modern apps
- **Shadow DOM and iframes:** scans inside open and closed shadow roots (web components) and same-origin iframes, nested to any depth. Selectors that cross these boundaries are written `host >>> inner`.
- **Single-page apps:** notices route changes (`history.pushState`, `#/hash` routes) without a reload, marks earlier results as out of date, and can rescan automatically.

### ✅ Review workflow
- **Triage:** mark each finding *Confirmed*, *False positive* or *Accepted risk*. Reviews are saved per site and reapplied on every scan; dismissed findings drop out of the counts.
- **Scan comparison:** every scan is compared with the previous scan of the same page, showing what's **new**, **fixed** and unchanged.

### 🧰 Developer tooling
- **Console capture** from `document_start`: errors, unhandled rejections, failed resources and CSP violations.
- **JavaScript runner** with ready-made snippets (network requests, forms, storage dump, live DOM-sink monitor, `postMessage` listeners…). Inside the DevTools panel it can still run code on pages whose CSP blocks `eval`.
- **Element inspector & editor:** point-and-click picker; read, edit, enable or unhide elements to check what the server re-validates.
- **Recon view:** response headers, cookie flags, detected libraries, endpoints pulled from JS, scripts, storage and custom globals.
- **Export** reports as Markdown or JSON.

### 🤖 Optional AI assistant
- Explains and prioritises findings, with attack scenarios, likely false positives, DevTools verification steps and fixes.
- Generates read-only DevTools scripts from a plain-English task, in a fast mode that limits the model's thinking time.
- Streams answers as they are written, with a live timer and a **Stop** button.
- Picks a usable model automatically, falls back across models and API keys, and gives up on a stalled model after 20–25 seconds.
- Only the **findings summary** is sent. Page HTML and cookie values are never sent.

## Installation

```bash
git clone https://github.com/i12hacku/DOM-Sentinel.git
```

1. Open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and select the cloned folder.
3. **Reload any tabs that were already open**, so console capture starts at page load.

No build step and no dependencies.

## Usage

1. Open the target site.
2. Click the DOM Sentinel toolbar icon (side panel), **or** press `F12` and open the **Security** tab.
3. Click **Scan page**. Turn on **Active checks** only if you are authorised.
4. Go through the **Findings**, **Hidden**, **Recon** and **Console** tabs.
5. *(Optional)* Add a Gemini API key under **⚙ Settings** and use the **AI** tab.

### Try it locally

The repo includes an intentionally insecure test page:

```bash
python -m http.server 8765
```

Open `http://localhost:8765/test/vulnerable-test-page.html?q=hello` and scan it. It also contains a web component with a hidden admin form, a same-origin iframe, and buttons that change the route without a reload.

## Development

No dependencies to install, just Node.js 22 or newer.

```bash
npm run check
```

Checks that the manifest is valid, that every file it references exists, that icon sizes match, and that every JavaScript file parses.

```bash
npm test
```

Runs the unit tests for the rule engine (`lib/rules.js`) and the streaming AI client (`lib/ai.js`, against a simulated Gemini API).

GitHub Actions runs both on every push and pull request, and attaches an installable `dom-sentinel-<version>.zip` to each run.

## Architecture

```
┌──────────────────────────┐      runtime messages      ┌─────────────────────────────┐
│  UI  (ui/panel.*)        │ ─────────────────────────▶ │  Service worker             │
│  • Side panel            │ ◀───────────────────────── │  background.js              │
│  • DevTools panel        │                            │  • scan orchestration       │
└──────────────────────────┘                            │  • webRequest header capture│
                                                        │  • cookies / script fetch   │
                                                        │  • lib/rules.js  (analysis) │
                                                        │  • lib/ai.js     (optional) │
                                                        └──────────────┬──────────────┘
                                                                       │ chrome.scripting
                                       ┌───────────────────────────────┴──────────────┐
                                       │  Page                                        │
                                       │  • injected/page-agent.js   (isolated world) │
                                       │  • injected/console-hook.js (main world)     │
                                       └──────────────────────────────────────────────┘
```

| Path | Purpose |
| --- | --- |
| `manifest.json` | MV3 manifest: side panel, DevTools page, document-start console hook |
| `background.js` | Service worker: orchestration, header capture, cookie and script analysis |
| `lib/rules.js` | Pure analysis rules for headers, cookies, secrets, JWTs, libraries, endpoints and console |
| `lib/ai.js` | Optional Gemini client with auto model selection, retry/backoff and key failover |
| `injected/page-agent.js` | On-demand DOM scanner, hidden-element engine, picker and editor |
| `injected/console-hook.js` | Captures console output, errors and CSP violations from page start |
| `ui/` | Shared UI for the side panel and the DevTools panel |
| `devtools/` | Registers the DevTools panel and the Elements sidebar |
| `test/` | Insecure demo page and a UI preview harness |
| `test/unit/` | Unit tests (`npm test`) |
| `scripts/check-extension.mjs` | Static extension checks (`npm run check`) |
| `icons/` | Extension icons, and `make-icons.ps1` to regenerate them from `logo.jfif` |
| `.github/workflows/ci.yml` | CI: check, test and package on every push |

## Permissions

| Permission | Why |
| --- | --- |
| `scripting` | Inject the scanner into the tab you are analysing |
| `webRequest` | Read main-frame response headers, including `Set-Cookie` (observe only, never blocks) |
| `cookies` | Check cookie flags, including HttpOnly cookies |
| `tabs`, `sidePanel` | Follow the active tab and show the side panel |
| `storage` | Save settings and per-tab scan results locally |
| `<all_urls>` | Scan any site you open, and fetch its scripts for analysis |

## Privacy & safety

- All scanning happens **locally in your browser**. Nothing is sent anywhere unless you use the AI tab.
- The API key stays in `chrome.storage.local` and is sent only to Google in a request header.
- Secret values are **masked** in findings and exports.
- The extension UI renders page data with `textContent` only, so a hostile page cannot inject into it.
- Active checks are **off by default**. They send only a few `GET` requests to the same origin.

## Limitations

- Findings are heuristic. Always confirm them manually before reporting.
- Library vulnerability detection is version-based and covers a curated set of libraries.
- Wrapping `console.*` makes DevTools show `console-hook.js` as the source line for page logs.
- Browser-internal pages (`chrome://`, the Chrome Web Store) cannot be scanned.
- Cross-origin iframes are skipped: browsers don't let extensions read into them from the parent page. Open the frame's URL in its own tab to scan it.

## Roadmap

- [x] Shadow DOM and same-origin iframe scanning *(2.2.0)*
- [x] Finding reviews and scan comparison *(2.2.0)*
- [x] Single-page app route tracking *(2.2.0)*
- [ ] API traffic view (XHR / fetch headers and responses)
- [ ] Open-redirect and postMessage live monitor
- [ ] HTML report export
- [ ] Custom rule packs (JSON)
- [ ] SARIF export
- [ ] Firefox (MV3) support

## Contributing

Issues and pull requests are welcome. Keep new rules in `lib/rules.js` as pure functions with a test in `test/unit/rules.test.js`, run `npm run check && npm test`, and try the change against `test/vulnerable-test-page.html`.

## Disclaimer

This tool is for **education and authorised security testing only**. You are responsible for following all applicable laws and the terms of any system you test.
