require("dotenv").config();

const express = require("express");
const cors = require("cors");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const OPENROUTER_URL = process.env.OPENROUTER_URL || "https://openrouter.ai/api/v1/chat/completions";
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || "";
const OPENROUTER_MODEL_FAST = process.env.OPENROUTER_MODEL_FAST || "deepseek/deepseek-chat";
const OPENROUTER_MODEL_HEAVY = process.env.OPENROUTER_MODEL_HEAVY || "deepseek/deepseek-v3.2";
const OPENROUTER_MODEL_QUICK_SUGGEST =
  process.env.OPENROUTER_MODEL_QUICK_SUGGEST || "deepseek/deepseek-v4-flash:free";
const OPENROUTER_TIMEOUT_FAST_MS = Number(process.env.OPENROUTER_TIMEOUT_FAST_MS || 12000);
const OPENROUTER_TIMEOUT_HEAVY_MS = Number(process.env.OPENROUTER_TIMEOUT_HEAVY_MS || 25000);

const ALLOWED_ORIGINS = String(process.env.CORS_ALLOWED_ORIGINS || "")
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);

const isObject = (value) => typeof value === "object" && value !== null;
const estimateTokens = (text) => Math.ceil(String(text || "").length / 4);

const toNumber = (value) => {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const normalized = value
      .toLowerCase()
      .replace(/rp/gi, "")
      .replace(/juta/gi, "000000")
      .replace(/ribu/gi, "000")
      .replace(/[^\d-]/g, "");
    const parsed = Number(normalized);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
};

const classifyIntent = (prompt) => {
  const text = String(prompt || "").toLowerCase();
  const heavyHints = [
    "analisis",
    "analysis",
    "laporan",
    "report",
    "cashflow",
    "arus kas",
    "forecast",
    "budget",
    "hutang",
    "net worth",
  ];
  return heavyHints.some((hint) => text.includes(hint)) ? "analysis" : "simple";
};

const resolveModelPlan = (prompt) => {
  const intent = classifyIntent(prompt);
  const primary = intent === "simple" ? OPENROUTER_MODEL_FAST : OPENROUTER_MODEL_HEAVY;
  const secondary = intent === "simple" ? OPENROUTER_MODEL_HEAVY : OPENROUTER_MODEL_FAST;
  const primaryTimeout = intent === "simple" ? OPENROUTER_TIMEOUT_FAST_MS : OPENROUTER_TIMEOUT_HEAVY_MS;
  const secondaryTimeout =
    intent === "simple" ? OPENROUTER_TIMEOUT_HEAVY_MS : OPENROUTER_TIMEOUT_FAST_MS;
  const maxTokens = intent === "simple" ? 260 : 520;
  return { intent, primary, secondary, primaryTimeout, secondaryTimeout, maxTokens };
};

const compactObject = (obj = {}) =>
  Object.fromEntries(Object.entries(obj).filter(([, value]) => Number(value) !== 0));

const buildCompactData = (currentData) => ({
  metadata: currentData?.metadata || {},
  personalFinance: {
    income: compactObject(currentData?.income || currentData?.accounts?.revenue || {}),
    expenses: compactObject(currentData?.expenses || currentData?.accounts?.expenses || {}),
    savings: compactObject(currentData?.savings || {}),
    debts: compactObject(currentData?.debts || currentData?.accounts?.liabilities || {}),
    assets: compactObject(currentData?.assets || currentData?.accounts?.assets || {}),
    budgets: currentData?.budgets || {},
    goals: currentData?.goals || {},
  },
  recentTransactions: Array.isArray(currentData?.transactions)
    ? currentData.transactions.slice(-20).map((tx) => ({
        id: tx?.id,
        date: tx?.date,
        description: tx?.description,
        amount: tx?.amount,
        type: tx?.type,
        category: tx?.category,
      }))
    : [],
});

const buildSystemInstruction = (targetLanguage, compactData) => `You are an AI personal finance assistant for everyday users age 18-28.
Rules:
1) Only answer personal finance context: income, expenses, savings, debts, assets, budget, goals.
2) Use simple everyday language, not business accounting jargon.
3) Keep data-entry replies very short (1-2 sentences).
4) For analysis, use neat sections: Judul, Summary, Detail, Insight, Rekomendasi.
5) Response language must be ${targetLanguage}.
6) Numbers and examples should be clear and simple for end users.
7) Do not output JSON patch blocks. Reply in natural language only.
Compact context:
${JSON.stringify(compactData)}`;

const evaluateSimpleMath = (expr) => {
  const compact = String(expr || "").replace(/\s+/g, "");
  if (!/^-?\d+(?:\.\d+)?(?:[+-]-?\d+(?:\.\d+)?)+$/.test(compact)) return null;
  const tokens = compact.match(/[+-]?\d+(?:\.\d+)?/g);
  if (!tokens?.length) return null;
  let total = 0;
  for (const token of tokens) {
    const value = Number(token);
    if (!Number.isFinite(value)) return null;
    total += value;
  }
  return total;
};

const normalizePatchJson = (rawPatch) => {
  let cleaned = String(rawPatch || "").trim();
  if (!cleaned) return cleaned;

  cleaned = cleaned.replace(/^\uFEFF/, "");
  cleaned = cleaned.replace(/[“”]/g, '"').replace(/[‘’]/g, "'");
  cleaned = cleaned.replace(/,\s*([}\]])/g, "$1");
  cleaned = cleaned.replace(/([:\[,]\s*)\+(\d+(?:\.\d+)?)/g, "$1$2");
  cleaned = cleaned.replace(
    /(:\s*)(-?\d+(?:\.\d+)?(?:\s*[+-]\s*-?\d+(?:\.\d+)?)+)(\s*[,}\]])/g,
    (_match, prefix, expr, suffix) => {
      const evaluated = evaluateSimpleMath(String(expr));
      return evaluated === null ? `${prefix}${expr}${suffix}` : `${prefix}${evaluated}${suffix}`;
    }
  );
  return cleaned;
};

const parsePatchPayload = (patchStr) => {
  try {
    return JSON.parse(patchStr);
  } catch {
    return JSON.parse(normalizePatchJson(patchStr));
  }
};

const applyPatch = (currentData, aiText) => {
  let finalData = JSON.parse(JSON.stringify(currentData || {}));
  let textWithoutJson = String(aiText || "");
  const jsonMatch = textWithoutJson.match(/\`\`\`json\n?([\s\S]*?)\n?\`\`\`/);
  let patchStr = "";

  if (jsonMatch) {
    patchStr = jsonMatch[1];
    textWithoutJson = textWithoutJson.replace(/\`\`\`json\n?([\s\S]*?)\n?\`\`\`/, "").trim();
  } else if (textWithoutJson.includes('"balanceUpdates"') || textWithoutJson.includes('"accountUpdates"')) {
    const fallbackMatch = textWithoutJson.match(/({[\s\S]*(?:"balanceUpdates"|"accountUpdates")[\s\S]*})/);
    if (fallbackMatch) {
      patchStr = fallbackMatch[1];
      textWithoutJson = textWithoutJson.replace(
        /({[\s\S]*(?:"balanceUpdates"|"accountUpdates")[\s\S]*})/,
        ""
      ).trim();
    }
  }

  if (!patchStr) return { finalData, textWithoutJson };

  try {
    const updates = parsePatchPayload(patchStr);
    const explicitBalanceUpdates = new Set();
    if (Array.isArray(updates.balanceUpdates)) {
      for (const update of updates.balanceUpdates) {
        if (!update?.section || !update?.name || typeof update?.value !== "number") continue;
        explicitBalanceUpdates.add(`${update.section}:${update.name}`);
        if (!isObject(finalData[update.section])) finalData[update.section] = {};
        finalData[update.section][update.name] = update.value;
      }
    }

    if (Array.isArray(updates.accountUpdates)) {
      if (!isObject(finalData.accounts)) finalData.accounts = {};
      for (const update of updates.accountUpdates) {
        if (!update?.category || !update?.name || typeof update?.value !== "number") continue;
        if (!isObject(finalData.accounts[update.category])) finalData.accounts[update.category] = {};
        finalData.accounts[update.category][update.name] = update.value;
      }
    }

    if (Array.isArray(updates.budgetUpdates)) {
      if (!isObject(finalData.budgets)) finalData.budgets = {};
      for (const update of updates.budgetUpdates) {
        if (!update?.name) continue;
        finalData.budgets[update.name] = {
          limit: toNumber(update.limit) || toNumber(finalData.budgets[update.name]?.limit) || 0,
          spent: toNumber(update.spent) || toNumber(finalData.budgets[update.name]?.spent) || 0,
        };
      }
    }

    if (Array.isArray(updates.goalUpdates)) {
      if (!isObject(finalData.goals)) finalData.goals = {};
      for (const update of updates.goalUpdates) {
        if (!update?.name) continue;
        finalData.goals[update.name] = {
          target: toNumber(update.target) || toNumber(finalData.goals[update.name]?.target) || 0,
          current: toNumber(update.current) || toNumber(finalData.goals[update.name]?.current) || 0,
          deadline: update.deadline || finalData.goals[update.name]?.deadline,
        };
      }
    }

    if (Array.isArray(updates.newTransactions)) {
      if (!Array.isArray(finalData.transactions)) finalData.transactions = [];
      const existingIds = new Set(finalData.transactions.map((tx) => (tx?.id ? String(tx.id) : "")));
      for (const tx of updates.newTransactions) {
        const id = tx?.id ? String(tx.id) : "";
        if (id && existingIds.has(id)) continue;
        const amount = toNumber(tx?.amount);
        const type = String(tx?.type || "");
        const category = String(tx?.category || "Lainnya");

        finalData.transactions.push({ ...tx, amount, category });
        if (id) existingIds.add(id);

        const addToSection = (section, name, delta) => {
          if (explicitBalanceUpdates.has(`${section}:${name}`)) return;
          if (!isObject(finalData[section])) finalData[section] = {};
          finalData[section][name] = Number(finalData[section][name] || 0) + delta;
        };

        if (type === "income") addToSection("income", category, amount);
        if (type === "expense") addToSection("expenses", category, amount);
        if (type === "saving") addToSection("savings", category, amount);
        if (type === "asset") addToSection("assets", category, amount);
        if (type === "debt_payment") {
          addToSection("expenses", "Cicilan", amount);
          if (isObject(finalData.debts) && typeof finalData.debts[category] === "number") {
            addToSection("debts", category, -amount);
          }
        }
      }
    }
  } catch (error) {
    const patchPreview = String(patchStr || "").replace(/\s+/g, " ").slice(0, 300);
    console.error("Patch snippet:", patchPreview);
    console.error("Failed to parse AI JSON patch:", error);
  }

  return { finalData, textWithoutJson };
};

const openRouterFetch = async ({ model, timeoutMs, messages, maxTokens, stream, referer }) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(OPENROUTER_URL, {
      method: "POST",
      signal: controller.signal,
      headers: {
        Authorization: `Bearer ${OPENROUTER_API_KEY}`,
        "Content-Type": "application/json",
        "HTTP-Referer": referer || "http://localhost:3000",
        "X-Title": "Dompetku BackendOnly",
      },
      body: JSON.stringify({
        model,
        temperature: 0.15,
        max_tokens: maxTokens,
        stream: Boolean(stream),
        messages,
      }),
    });

    if (!response.ok) {
      const err = await response.text();
      throw new Error(`OpenRouter Error ${response.status}: ${err}`);
    }

    return response;
  } finally {
    clearTimeout(timeout);
  }
};

const callOpenRouterText = async (params) => {
  const startedAt = Date.now();
  const response = await openRouterFetch({ ...params, stream: false });
  const data = await response.json();
  const text = data?.choices?.[0]?.message?.content || "";
  return { text, ttftMs: Date.now() - startedAt, totalMs: Date.now() - startedAt };
};

const streamOpenRouterText = async (params) => {
  const startedAt = Date.now();
  let firstTokenAt = 0;
  let fullText = "";
  const response = await openRouterFetch({ ...params, stream: true });

  const reader = response.body?.getReader();
  if (!reader) throw new Error("Streaming body not available.");

  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line.startsWith("data:")) continue;
      const payload = line.slice(5).trim();
      if (!payload || payload === "[DONE]") continue;

      let parsed = null;
      try {
        parsed = JSON.parse(payload);
      } catch {
        continue;
      }

      const token = parsed?.choices?.[0]?.delta?.content || "";
      if (!token) continue;
      if (!firstTokenAt) firstTokenAt = Date.now();
      fullText += token;
      params.onToken(token);
    }
  }

  return {
    fullText,
    ttftMs: firstTokenAt ? firstTokenAt - startedAt : Date.now() - startedAt,
    totalMs: Date.now() - startedAt,
  };
};

app.use(express.json({ limit: "10mb" }));
app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (!ALLOWED_ORIGINS.length || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
      return callback(new Error(`Origin not allowed: ${origin}`));
    },
  })
);

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    app: "Dompetku-BackendOnly",
    env: process.env.NODE_ENV || "development",
    openrouterKeyLoaded: Boolean(OPENROUTER_API_KEY),
    models: {
      fast: OPENROUTER_MODEL_FAST,
      heavy: OPENROUTER_MODEL_HEAVY,
    },
  });
});

app.post("/api/chat", async (req, res) => {
  const started = Date.now();
  try {
    const { prompt, currentData, language } = req.body || {};
    const targetLanguage = language || "Indonesian";
    const { primary, secondary, primaryTimeout, secondaryTimeout, maxTokens } =
      resolveModelPlan(prompt || "");
    const compactData = buildCompactData(currentData || {});
    const systemInstruction = buildSystemInstruction(targetLanguage, compactData);
    const messages = [
      { role: "system", content: systemInstruction },
      { role: "user", content: String(prompt || "") },
    ];

    let usedModel = primary;
    let fallbackUsed = false;
    let aiText = "";
    let timing = { ttftMs: 0, totalMs: 0 };

    try {
      const result = await callOpenRouterText({
        model: primary,
        timeoutMs: primaryTimeout,
        messages,
        maxTokens,
        referer: req.headers.referer,
      });
      aiText = result.text;
      timing = { ttftMs: result.ttftMs, totalMs: result.totalMs };
    } catch (error) {
      fallbackUsed = true;
      usedModel = secondary;
      const result = await callOpenRouterText({
        model: secondary,
        timeoutMs: secondaryTimeout,
        messages,
        maxTokens: Math.max(maxTokens, 400),
        referer: req.headers.referer,
      });
      aiText = result.text;
      timing = { ttftMs: result.ttftMs, totalMs: result.totalMs };
      console.warn("Primary model failed, fallback used:", String(error));
    }

    const textWithoutJson = String(aiText || "")
      .replace(/\`\`\`json\n?[\s\S]*?\n?\`\`\`/g, "")
      .trim();
    console.log(
      "[latency]",
      JSON.stringify({
        route: "/api/chat",
        ttft_ms: timing.ttftMs,
        total_ms: Date.now() - started,
        input_chars: String(prompt || "").length,
        output_tokens_est: estimateTokens(aiText),
        model_used: usedModel,
        fallback_used: fallbackUsed,
      })
    );
    res.json({
      text: textWithoutJson,
      metadata: {
        processing_mode: "ai_proxy",
        model_used: usedModel,
        fallback_used: fallbackUsed,
        ttft_ms: timing.ttftMs,
        total_ms: Date.now() - started,
      },
    });
  } catch (error) {
    console.error("AI Proxy Error:", error);
    res.status(500).json({ error: error?.message || "Unknown error" });
  }
});

app.post("/api/chat/stream", async (req, res) => {
  const started = Date.now();
  const sendEvent = (event, data) => {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  try {
    const { prompt, currentData, language } = req.body || {};
    const targetLanguage = language || "Indonesian";
    const { primary, secondary, primaryTimeout, secondaryTimeout, maxTokens } =
      resolveModelPlan(prompt || "");
    const compactData = buildCompactData(currentData || {});
    const systemInstruction = buildSystemInstruction(targetLanguage, compactData);
    const messages = [
      { role: "system", content: systemInstruction },
      { role: "user", content: String(prompt || "") },
    ];

    res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    let usedModel = primary;
    let fallbackUsed = false;
    let fullText = "";
    let hasEmittedToken = false;
    let ttftMs = 0;

    const runStream = async (model, timeoutMs, tokenBudget) => {
      const streamResult = await streamOpenRouterText({
        model,
        timeoutMs,
        messages,
        maxTokens: tokenBudget,
        referer: req.headers.referer,
        onToken: (chunk) => {
          hasEmittedToken = true;
          fullText += chunk;
          sendEvent("token", { textChunk: chunk });
        },
      });
      ttftMs = streamResult.ttftMs;
    };

    try {
      await runStream(primary, primaryTimeout, maxTokens);
    } catch (error) {
      if (hasEmittedToken) throw error;
      fallbackUsed = true;
      usedModel = secondary;
      await runStream(secondary, secondaryTimeout, Math.max(maxTokens, 400));
      console.warn("Primary stream failed, fallback used:", String(error));
    }

    const textWithoutJson = String(fullText || "")
      .replace(/\`\`\`json\n?[\s\S]*?\n?\`\`\`/g, "")
      .trim();
    console.log(
      "[latency]",
      JSON.stringify({
        route: "/api/chat/stream",
        ttft_ms: ttftMs,
        total_ms: Date.now() - started,
        input_chars: String(prompt || "").length,
        output_tokens_est: estimateTokens(fullText),
        model_used: usedModel,
        fallback_used: fallbackUsed,
      })
    );

    sendEvent("done", {
      fullText: textWithoutJson,
      metadata: {
        processing_mode: "ai_proxy",
        model_used: usedModel,
        fallback_used: fallbackUsed,
        ttft_ms: ttftMs,
        total_ms: Date.now() - started,
      },
    });
    res.end();
  } catch (error) {
    console.error("AI Stream Error:", error);
    sendEvent("error", { message: error?.message || "Streaming failed" });
    res.end();
  }
});

app.post("/api/quick-suggestions", async (req, res) => {
  try {
    const { text, language } = req.body || {};
    const query = String(text || "").trim();
    if (!query) return res.json({ suggestions: [] });

    const prompt = `User is typing this request: "${query}".
Generate exactly 3 short quick suggestions for a personal finance assistant app.
Rules:
- Language: ${language || "Indonesian"}
- Each suggestion max 10 words
- Practical and directly actionable
- No numbering, no markdown, no explanation
- Return valid JSON object only: {"suggestions":["...","...","..."]}`;

    const result = await callOpenRouterText({
      model: OPENROUTER_MODEL_QUICK_SUGGEST,
      timeoutMs: 12000,
      maxTokens: 120,
      referer: req.headers.referer,
      messages: [{ role: "user", content: prompt }],
    });

    let parsed = null;
    const textResult = String(result.text || "").trim();
    try {
      parsed = JSON.parse(textResult);
    } catch {
      const match = textResult.match(/\{[\s\S]*\}/);
      if (match) parsed = JSON.parse(match[0]);
    }

    const suggestions = Array.isArray(parsed?.suggestions)
      ? parsed.suggestions.map((v) => String(v || "").trim()).filter(Boolean).slice(0, 3)
      : [];

    if (!suggestions.length) throw new Error("No suggestions returned");
    return res.json({ suggestions });
  } catch (error) {
    return res.status(503).json({ error: error?.message || "Quick suggestions unavailable" });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`BackendOnly running on http://0.0.0.0:${PORT}`);
});
