// Optional AI layer (Google Gemini). The scanner works fully without it.
// Keys are sent in the x-goog-api-key header (not the URL) and stay in chrome.storage.local.

const ROOT = "https://generativelanguage.googleapis.com/v1beta";

export async function getAiSettings() {
  const s = await chrome.storage.local.get(["aiKeys", "aiModel", "geminiApiKeys"]);
  const keys = (Array.isArray(s.aiKeys) ? s.aiKeys : Array.isArray(s.geminiApiKeys) ? s.geminiApiKeys : [])
    .map((k) => String(k || "").trim())
    .filter((k) => k.length > 20);
  return { keys, model: (s.aiModel || "auto").trim() || "auto" };
}

async function listModels(key) {
  const cache = await chrome.storage.session.get("modelCache");
  if (cache.modelCache && Date.now() - cache.modelCache.at < 6 * 3600e3) return cache.modelCache.models;
  const res = await fetch(`${ROOT}/models?pageSize=200`, { headers: { "x-goog-api-key": key } });
  if (!res.ok) throw new Error(`ListModels failed: ${await errorText(res)}`);
  const json = await res.json();
  const names = (json.models || [])
    .filter((m) => (m.supportedGenerationMethods || []).includes("generateContent"))
    .map((m) => m.name.replace(/^models\//, ""));
  const score = (n) => {
    let s = 0;
    if (!/^gemini/.test(n)) s -= 1000;
    if (/(image|tts|audio|live|embedding|vision|learnlm|aqa|robotics|computer-use|native)/.test(n)) s -= 1000;
    if (/flash/.test(n)) s += 100;
    if (/pro/.test(n)) s += 50;
    if (/lite/.test(n)) s -= 10;
    if (/(preview|exp)/.test(n)) s -= 40;
    if (/-latest$/.test(n)) s += 5;
    s += 20 * parseFloat((n.match(/gemini-(\d+(?:\.\d+)?)/) || [])[1] || 0);
    return s;
  };
  const models = names.filter((n) => score(n) > 0).sort((a, b) => score(b) - score(a));
  await chrome.storage.session.set({ modelCache: { at: Date.now(), models } });
  return models;
}

async function errorText(res) {
  const t = await res.text();
  try { return `HTTP ${res.status}: ${JSON.parse(t).error.message}`; } catch (_) { return `HTTP ${res.status}: ${t.slice(0, 300)}`; }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const MAX_TOKEN_CEILING = 32768;

// One model, with retries: 503/500/429 → back off and retry; MAX_TOKENS with no
// text (thinking models spend the budget on reasoning) → retry with a bigger budget.
async function tryModel(key, m, prompt, temperature, maxOutputTokens, log) {
  let budget = maxOutputTokens;
  for (let attempt = 1; attempt <= 4; attempt++) {
    let res;
    try {
      res = await fetch(`${ROOT}/models/${encodeURIComponent(m)}:generateContent`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-goog-api-key": key },
        body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: prompt }] }], generationConfig: { temperature, maxOutputTokens: budget } })
      });
    } catch (e) {
      log(`${m}: network error ${e.message}`);
      await sleep(1000 * attempt);
      continue;
    }

    if (!res.ok) {
      const msg = await errorText(res);
      if (res.status === 400 && /API key not valid/i.test(msg)) return { fatalKey: msg };
      const transient = res.status === 503 || res.status === 500 || res.status === 504 || (res.status === 429 && !/limit:\s*0|exceeded your current quota/i.test(msg));
      log(`${m}: ${msg.slice(0, 160)}${transient && attempt < 3 ? " (retrying)" : ""}`);
      if (transient && attempt < 3) {
        const retryAfter = Number(res.headers.get("retry-after")) || 0;
        await sleep(Math.min(retryAfter * 1000 || 1500 * 2 ** (attempt - 1), 8000));
        continue;
      }
      return null; // 404 / hard quota / persistent overload → next model
    }

    const json = await res.json();
    const cand = json.candidates?.[0];
    const text = (cand?.content?.parts || []).filter((p) => !p.thought).map((p) => p.text || "").join("").trim();
    if (text) return { text: cand?.finishReason === "MAX_TOKENS" ? text + "\n\n[…output truncated]" : text, model: m };

    const reason = cand?.finishReason || json.promptFeedback?.blockReason || "unknown";
    if (reason === "MAX_TOKENS" && budget < MAX_TOKEN_CEILING) {
      budget = Math.min(budget * 4, MAX_TOKEN_CEILING);
      log(`${m}: used all tokens on thinking, retrying with ${budget}`);
      continue;
    }
    log(`${m}: empty response (${reason})`);
    return null;
  }
  return null;
}

export async function callAi(prompt, { temperature = 0.2, maxOutputTokens = 8192 } = {}) {
  const { keys, model } = await getAiSettings();
  if (!keys.length) throw new Error("No AI API key configured. Add one in the Settings tab (AI is optional — scanning works without it).");

  const errors = [];
  for (const [i, key] of keys.entries()) {
    const log = (msg) => errors.push(`key ${i + 1} / ${msg}`);
    let candidates;
    try {
      candidates = model === "auto" ? (await listModels(key)).slice(0, 6) : [model];
    } catch (e) {
      errors.push(`key ${i + 1}: ${e.message}`);
      continue;
    }
    if (!candidates.length) { errors.push(`key ${i + 1}: no usable Gemini models returned by ListModels`); continue; }

    for (const m of candidates) {
      const r = await tryModel(key, m, prompt, temperature, maxOutputTokens, log);
      if (r?.fatalKey) { errors.push(`key ${i + 1}: ${r.fatalKey}`); break; }
      if (r) return r;
    }
  }
  throw new Error("All AI attempts failed:\n" + errors.slice(-10).join("\n") +
    (errors.some((e) => /HTTP 503|high demand/i.test(e)) ? "\n\nGoogle's servers are overloaded right now — wait a minute and try again, or set a specific model (e.g. a -lite one) in Settings." : ""));
}

export function explainPrompt(report) {
  const findings = report.findings
    .filter((f) => f.severity !== "info")
    .slice(0, 60)
    .map((f) => ({ severity: f.severity, category: f.category, title: f.title, evidence: String(f.evidence || "").slice(0, 300) }));
  return `You are a senior web application security tester helping an authorized tester.
A passive browser scanner produced the findings below for ${report.url}.

Write a concise report in plain text (simple Markdown headings and bullets are fine):
1. "Top risks" — the 3-6 findings that matter most, why, and a realistic attack scenario for each.
2. "Likely false positives" — findings that are probably noise and why.
3. "How to verify in DevTools" — concrete, safe, non-destructive steps (Elements / Console / Network / Application panels).
4. "Fixes" — specific remediation for the developer.
Do not invent findings that are not supported by the evidence.

Libraries: ${JSON.stringify(report.libraries || [])}
Findings (JSON):
${JSON.stringify(findings, null, 1).slice(0, 24000)}`;
}

export function scriptPrompt(task, report) {
  return `Write a single JavaScript snippet to run in the Chrome DevTools Console on ${report?.url || "the current page"}.
Task: ${task}

Rules:
- Output ONLY JavaScript, no Markdown fences, no explanation outside code comments.
- Read-only and non-destructive: inspect and log, do not submit forms, delete data or send requests to third parties.
- Wrap in an async IIFE with try/catch; print results with console.table / console.log / console.warn.
- Make the last expression return a short summary object.

Context: page title "${report?.title || ""}", libraries ${JSON.stringify(report?.libraries || [])}, ${report?.stats?.forms ?? "?"} forms, ${report?.stats?.scripts ?? "?"} scripts.`;
}

export const stripFences = (t) => String(t || "").replace(/^\s*```(?:javascript|js)?\s*/i, "").replace(/\s*```\s*$/i, "").trim();
