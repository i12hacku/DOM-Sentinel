// Tests for lib/ai.js streamAi() against a simulated Gemini streaming API.
// Timers are sped up 500x so timeout paths run in milliseconds.
import { test, describe, beforeEach } from "node:test";
import assert from "node:assert/strict";

const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...a) => realSetTimeout(fn, Math.max(1, (ms || 0) / 500), ...a);

const store = { aiKeys: ["AIza" + "x".repeat(35)], aiModel: "auto" };
const session = {};
globalThis.chrome = {
  storage: {
    local: { get: async () => store },
    session: { get: async (k) => ({ [k]: session[k] }), set: async (o) => Object.assign(session, o) }
  }
};

const MODELS = ["gemini-9.1-flash", "gemini-9.0-flash", "gemini-8.0-flash-lite"];
let scenario = {};
let calls = [];
const enc = new TextEncoder();
const chunk = (text, finishReason) => ({ candidates: [{ content: { parts: [{ text }] }, ...(finishReason ? { finishReason } : {}) }] });

function sseStream(events, { stallAfter = Infinity, gapMs = 2 } = {}, signal) {
  let i = 0;
  return new ReadableStream({
    pull: (c) => new Promise((resolve, reject) => {
      signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
      if (i >= events.length) { try { c.close(); } catch (_) {} return resolve(); }
      if (i >= stallAfter) return; // never resolves: a stalled connection
      realSetTimeout(() => {
        try { c.enqueue(enc.encode(`data: ${JSON.stringify(events[i++])}\r\n\r\n`)); } catch (_) {}
        resolve();
      }, gapMs);
    })
  });
}

globalThis.fetch = async (url, opts = {}) => {
  if (url.includes("/models?")) {
    return new Response(JSON.stringify({ models: MODELS.map((n) => ({ name: "models/" + n, supportedGenerationMethods: ["generateContent"] })) }));
  }
  const model = url.match(/models\/([^:]+)/)[1];
  const cfg = JSON.parse(opts.body).generationConfig;
  calls.push({ model, thinking: cfg.thinkingConfig ?? null, max: cfg.maxOutputTokens });
  const behaviour = scenario[model] || "ok";
  if (behaviour === "503") return new Response(JSON.stringify({ error: { code: 503, message: "high demand" } }), { status: 503 });
  if (behaviour === "no-thinkingLevel" && cfg.thinkingConfig?.thinkingLevel) {
    return new Response(JSON.stringify({ error: { code: 400, message: "Unknown name \"thinkingLevel\" at 'generation_config.thinking_config'" } }), { status: 400 });
  }
  if (behaviour === "bad-key") return new Response(JSON.stringify({ error: { code: 400, message: "API key not valid." } }), { status: 400 });
  if (behaviour === "stall") return new Response(sseStream([chunk("partial "), chunk("never")], { stallAfter: 1 }, opts.signal));
  if (behaviour === "slow") return new Response(sseStream([chunk("a"), chunk("b"), chunk("c", "STOP")], { gapMs: 40 }, opts.signal));
  if (behaviour === "max-tokens-empty" && cfg.maxOutputTokens < 8000) return new Response(sseStream([{ candidates: [{ finishReason: "MAX_TOKENS" }] }], {}, opts.signal));
  return new Response(sseStream([chunk("Hello "), chunk("world"), chunk("!", "STOP")], {}, opts.signal));
};

const { streamAi } = await import("../../lib/ai.js");

async function run(sc, opts = {}, extra = {}) {
  scenario = sc;
  calls = [];
  const events = [];
  const result = await streamAi("prompt", opts, {
    onText: (t) => events.push(["text", t]),
    onStatus: (s) => events.push(["status", s]),
    onReset: () => events.push(["reset"]),
    ...extra
  });
  return { result, events, texts: events.filter((e) => e[0] === "text").map((e) => e[1]) };
}

describe("streamAi", () => {
  beforeEach(() => { store.aiModel = "auto"; });

  test("streams text chunks in order and returns the full answer", async () => {
    const { result, texts } = await run({});
    assert.deepEqual(texts, ["Hello ", "world", "!"]);
    assert.equal(result.text, "Hello world!");
    assert.equal(result.model, "gemini-9.1-flash");
  });

  test("normal requests send no thinking setting", async () => {
    await run({});
    assert.equal(calls[0].thinking, null);
  });

  test("fast mode falls back when a model rejects thinkingLevel, and remembers it", async () => {
    await run({ "gemini-9.1-flash": "no-thinkingLevel" }, { fast: true });
    assert.deepEqual(calls.map((c) => c.thinking), [{ thinkingLevel: "low" }, { thinkingBudget: 512 }]);
    await run({ "gemini-9.1-flash": "no-thinkingLevel" }, { fast: true });
    assert.deepEqual(calls.map((c) => c.thinking), [{ thinkingBudget: 512 }], "second run should not repeat the rejected setting");
  });

  test("a busy (503) model is retried once, then the next model answers", async () => {
    const { result } = await run({ "gemini-9.1-flash": "503" });
    assert.deepEqual(calls.map((c) => c.model), ["gemini-9.1-flash", "gemini-9.1-flash", "gemini-9.0-flash"]);
    assert.equal(result.model, "gemini-9.0-flash");
  });

  test("a stalled stream is abandoned and its partial text discarded", async () => {
    const { result, events } = await run({ "gemini-9.1-flash": "stall" });
    const kinds = events.map((e) => e[0]);
    assert.ok(kinds.indexOf("reset") > kinds.indexOf("text"), "partial text must be reset before the next model");
    assert.equal(result.model, "gemini-9.0-flash");
    assert.equal(result.text, "Hello world!");
  });

  test("an empty MAX_TOKENS answer is retried with a bigger budget", async () => {
    const { result } = await run({ "gemini-9.1-flash": "max-tokens-empty" }, { maxOutputTokens: 2048 });
    assert.deepEqual(calls.map((c) => c.max), [2048, 8192]);
    assert.equal(result.text, "Hello world!");
  });

  test("an invalid API key stops trying that key and reports it", async () => {
    await assert.rejects(run({ "gemini-9.1-flash": "bad-key" }), /API key not valid/);
    assert.equal(calls.length, 1);
  });

  test("aborting mid-stream throws a cancellation error", async () => {
    const ctrl = new AbortController();
    realSetTimeout(() => ctrl.abort(), 50);
    await assert.rejects(run({ "gemini-9.1-flash": "slow" }, {}, { signal: ctrl.signal }), { name: "AbortError" });
  });

  test("a configured model is used directly", async () => {
    store.aiModel = "gemini-8.0-flash-lite";
    const { result } = await run({});
    assert.equal(result.model, "gemini-8.0-flash-lite");
    assert.deepEqual(calls.map((c) => c.model), ["gemini-8.0-flash-lite"]);
  });
});
