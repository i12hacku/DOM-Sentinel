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
const FIRST_BYTE_TIMEOUT_MS = 25000; // give up on a model that hasn't started answering
const IDLE_TIMEOUT_MS = 20000;       // ...or that stops sending mid-answer

// Fast mode asks the model to think less. Different Gemini generations accept
// different fields, so try them in order and remember what each model accepts.
const THINKING_VARIANTS = [{ thinkingLevel: "low" }, { thinkingBudget: 512 }, null];
const thinkingSupport = new Map(); // model -> index into THINKING_VARIANTS

class Cancelled extends Error {
  constructor() { super("Cancelled."); this.name = "AbortError"; }
}

// One streaming request. Never throws for API/network problems (returns { error });
// throws Cancelled only when the caller aborts.
async function streamOnce({ key, model, prompt, temperature, maxOutputTokens, thinking, signal, onText }) {
  const ctrl = new AbortController();
  const onAbort = () => ctrl.abort("cancel");
  signal?.addEventListener("abort", onAbort);
  let timer = setTimeout(() => ctrl.abort("timeout"), FIRST_BYTE_TIMEOUT_MS);
  let text = "";
  try {
    const generationConfig = { temperature, maxOutputTokens, ...(thinking ? { thinkingConfig: thinking } : {}) };
    const res = await fetch(`${ROOT}/models/${encodeURIComponent(model)}:streamGenerateContent?alt=sse`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": key },
      body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: prompt }] }], generationConfig }),
      signal: ctrl.signal
    });
    if (!res.ok) return { status: res.status, error: await errorText(res), retryAfter: Number(res.headers.get("retry-after")) || 0 };

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    let finish = null;
    let block = null;
    for (;;) {
      clearTimeout(timer);
      timer = setTimeout(() => ctrl.abort("timeout"), IDLE_TIMEOUT_MS);
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n");
      let cut;
      while ((cut = buf.indexOf("\n\n")) >= 0) {
        const event = buf.slice(0, cut);
        buf = buf.slice(cut + 2);
        const data = event.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("");
        if (!data) continue;
        let json;
        try { json = JSON.parse(data); } catch (_) { continue; }
        if (json.error) return { status: json.error.code || 0, error: `HTTP ${json.error.code || "?"}: ${json.error.message}`, partial: text };
        const cand = json.candidates?.[0];
        const chunk = (cand?.content?.parts || []).filter((p) => !p.thought).map((p) => p.text || "").join("");
        if (chunk) { text += chunk; onText(chunk); }
        if (cand?.finishReason) finish = cand.finishReason;
        if (json.promptFeedback?.blockReason) block = json.promptFeedback.blockReason;
      }
    }
    return { text, finish, block };
  } catch (e) {
    if (signal?.aborted) throw new Cancelled();
    const timedOut = ctrl.signal.reason === "timeout";
    return { status: 0, timeout: timedOut, error: timedOut ? (text ? "stopped sending for 20s" : "no response within 25s") : `network error: ${e.message}`, partial: text };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}

// Streams an answer, failing over across models and keys.
//   onText(chunk)  – answer text as it arrives
//   onStatus(msg)  – what is happening ("Asking gemini-x", "busy, retrying")
//   onReset()      – discard text streamed so far (a retry is starting over)
export async function streamAi(prompt, { temperature = 0.2, maxOutputTokens = 8192, fast = false } = {}, { onText = () => {}, onStatus = () => {}, onReset = () => {}, signal } = {}) {
  const { keys, model } = await getAiSettings();
  if (!keys.length) throw new Error("No AI API key configured. Add one in the Settings tab (AI is optional — scanning works without it).");

  const errors = [];
  for (const [i, key] of keys.entries()) {
    const log = (msg) => errors.push(`key ${i + 1} / ${msg}`);
    let candidates;
    try {
      candidates = model === "auto" ? (await listModels(key)).slice(0, 5) : [model];
    } catch (e) {
      errors.push(`key ${i + 1}: ${e.message}`);
      continue;
    }
    if (!candidates.length) { errors.push(`key ${i + 1}: no usable Gemini models returned by ListModels`); continue; }

    nextModel:
    for (const m of candidates) {
      let budget = maxOutputTokens;
      let tIdx = fast ? (thinkingSupport.get(m) ?? 0) : THINKING_VARIANTS.length - 1;
      let busyRetried = false;
      for (let attempt = 0; attempt < 5; attempt++) {
        if (signal?.aborted) throw new Cancelled();
        onStatus(`Asking ${m}`);
        let streamed = false;
        const r = await streamOnce({
          key, model: m, prompt, temperature, maxOutputTokens: budget, thinking: THINKING_VARIANTS[tIdx], signal,
          onText: (t) => { streamed = true; onText(t); }
        });

        if (r.error) {
          if (streamed) onReset();
          if (r.status === 400 && /API key not valid/i.test(r.error)) { errors.push(`key ${i + 1}: ${r.error}`); break nextModel; }
          if (r.status === 400 && /thinking/i.test(r.error) && tIdx < THINKING_VARIANTS.length - 1) {
            tIdx += 1; // this model doesn't accept that thinking setting; try the next form
            thinkingSupport.set(m, tIdx);
            continue;
          }
          const busy = r.status === 503 || r.status === 500 || r.status === 504 || (r.status === 429 && !/limit:\s*0|exceeded your current quota/i.test(r.error));
          log(`${m}: ${r.error.slice(0, 160)}`);
          if (busy && !busyRetried) {
            busyRetried = true; // one short retry, then move on: another model is usually faster than waiting
            onStatus(`${m} is busy, retrying`);
            await sleep(Math.min(r.retryAfter * 1000 || 1500, 4000));
            continue;
          }
          onStatus(r.timeout ? `${m} timed out, trying another model` : `${m} failed, trying another model`);
          continue nextModel;
        }

        if (fast) thinkingSupport.set(m, tIdx);
        const text = r.text.trim();
        if (text) return { text: r.finish === "MAX_TOKENS" ? text + "\n\n[…output truncated]" : text, model: m };
        const reason = r.finish || r.block || "unknown";
        if (reason === "MAX_TOKENS" && budget < MAX_TOKEN_CEILING) {
          budget = Math.min(budget * 4, MAX_TOKEN_CEILING);
          onStatus(`${m} ran out of tokens while thinking, retrying with more`);
          continue;
        }
        log(`${m}: empty response (${reason})`);
        continue nextModel;
      }
    }
  }
  throw new Error("All AI attempts failed:\n" + errors.slice(-10).join("\n") +
    (errors.some((e) => /HTTP 503|high demand/i.test(e)) ? "\n\nGoogle's servers are overloaded right now — wait a minute and try again, or set a specific model (e.g. a -lite one) in Settings." : ""));
}

// Non-streaming convenience wrapper (used by "Test AI").
export const callAi = (prompt, opts = {}) => streamAi(prompt, opts);

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
