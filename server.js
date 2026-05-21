require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const { JWT } = require("google-auth-library");

const app = express();
const pendingActionConfirmations = new Map();
const ACTION_CONFIRM_TTL_MS = 10 * 60 * 1000;

const PORT = Number(process.env.PORT || 3000);
const OPENROUTER_URL = process.env.OPENROUTER_URL || "https://openrouter.ai/api/v1/chat/completions";
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || "";
const OPENROUTER_MODEL_FAST = process.env.OPENROUTER_MODEL_FAST || "deepseek/deepseek-v4-flash";
const OPENROUTER_MODEL_HEAVY = process.env.OPENROUTER_MODEL_HEAVY || "deepseek/deepseek-v4-flash";
const OPENROUTER_MODEL_QUICK_SUGGEST =
  process.env.OPENROUTER_MODEL_QUICK_SUGGEST || "deepseek/deepseek-v4-flash:free";
const OPENROUTER_MODEL_FREE = process.env.OPENROUTER_MODEL_FREE || "deepseek/deepseek-v4-flash:free";
const OPENROUTER_MODEL_REPORT_RECOMMENDATION =
  process.env.OPENROUTER_MODEL_REPORT_RECOMMENDATION || "deepseek/deepseek-v4-flash:free";
const OPENROUTER_TIMEOUT_FAST_MS = Number(process.env.OPENROUTER_TIMEOUT_FAST_MS || 12000);
const OPENROUTER_TIMEOUT_HEAVY_MS = Number(process.env.OPENROUTER_TIMEOUT_HEAVY_MS || 25000);
const hasOpenRouterKey = () => Boolean(OPENROUTER_API_KEY.trim());
const assertOpenRouterKey = () => {
  if (!hasOpenRouterKey()) {
    throw new Error("Server AI belum membaca OPENROUTER_API_KEY.");
  }
};
const logAiRoute = (route, details = {}) => {
  console.log(
    "[ai-route]",
    JSON.stringify({
      route,
      hasOpenRouterKey: hasOpenRouterKey(),
      modelFree: OPENROUTER_MODEL_FREE,
      modelReport: OPENROUTER_MODEL_REPORT_RECOMMENDATION,
      ...details,
    })
  );
};

const resolveGoogleServiceAccount = () => {
  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    const parsed = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    return {
      clientEmail: parsed.client_email,
      privateKey: String(parsed.private_key || "").replace(/\\n/g, "\n"),
    };
  }

  return {
    clientEmail: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || "",
    privateKey: String(process.env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
  };
};

const getGooglePlayAccessToken = async () => {
  const { clientEmail, privateKey } = resolveGoogleServiceAccount();
  if (!clientEmail || !privateKey) {
    throw new Error("Google service account credentials are missing.");
  }

  const client = new JWT({
    email: clientEmail,
    key: privateKey,
    scopes: ["https://www.googleapis.com/auth/androidpublisher"],
  });
  const token = await client.getAccessToken();
  if (!token.token) throw new Error("Failed to obtain Google Play access token.");
  return token.token;
};

const verifyGoogleSubscription = async (purchaseToken) => {
  if (!GOOGLE_PLAY_PACKAGE_NAME) {
    throw new Error("GOOGLE_PLAY_PACKAGE_NAME is missing.");
  }

  const accessToken = await getGooglePlayAccessToken();
  const response = await fetch(
    `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${encodeURIComponent(
      GOOGLE_PLAY_PACKAGE_NAME
    )}/purchases/subscriptionsv2/tokens/${encodeURIComponent(purchaseToken)}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }
  );

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Google Play verify failed (${response.status}): ${err}`);
  }

  return response.json();
};

const verifySupabaseUserAccessToken = async (accessToken) => {
  if (!accessToken) throw new Error("Missing Supabase access token.");

  const response = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    headers: {
      apikey: SUPABASE_PUBLISHABLE_KEY,
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Supabase auth verification failed (${response.status}): ${err}`);
  }

  return response.json();
};

const getBearerTokenFromRequest = (req) => {
  const authHeader = String(req.headers.authorization || "");
  return authHeader.toLowerCase().startsWith("bearer ") ? authHeader.slice(7).trim() : "";
};

const requireSupabaseUser = async (req, res, next) => {
  try {
    const accessToken = getBearerTokenFromRequest(req);
    if (!accessToken) {
      return res.status(401).json({ error: "Login session tidak ditemukan." });
    }
    const authUser = await verifySupabaseUserAccessToken(accessToken);
    if (!authUser?.id) {
      return res.status(401).json({ error: "Session Supabase tidak valid." });
    }
    req.authUser = {
      id: String(authUser.id),
      email: authUser.email || null,
    };
    return next();
  } catch (error) {
    return res.status(401).json({ error: error?.message || "Session Supabase tidak valid." });
  }
};

const readAccessOverrideByUserId = async (userId) => {
  const rows = await supabaseRestFetch(
    `${ACCESS_OVERRIDE_TABLE}?user_id=eq.${encodeURIComponent(
      userId
    )}&select=role,daily_task_limit,input_char_limit,note,updated_at&limit=1`
  );
  const row = firstRow(rows);
  if (!row) return null;
  return {
    role: row.role === "admin" ? "admin" : "user",
    daily_task_limit: Number(row.daily_task_limit) || 5,
    input_char_limit: Number(row.input_char_limit) || 50,
    note: row.note || null,
    updated_at: row.updated_at || null,
  };
};

const mapPromoError = (message) => {
  if (message.includes("PROMO_NOT_FOUND")) return "PROMO_NOT_FOUND";
  if (message.includes("PROMO_INACTIVE")) return "PROMO_INACTIVE";
  if (message.includes("PROMO_EXPIRED")) return "PROMO_EXPIRED";
  if (message.includes("PROMO_QUOTA_EXCEEDED")) return "PROMO_QUOTA_EXCEEDED";
  if (message.includes("PROMO_ALREADY_REDEEMED")) return "PROMO_ALREADY_REDEEMED";
  if (message.includes("PROMO_INVALID_REWARD")) return "PROMO_INVALID_REWARD";
  return "PROMO_REDEEM_FAILED";
};

const cleanupExpiredActionConfirmations = () => {
  const now = Date.now();
  for (const [id, item] of pendingActionConfirmations.entries()) {
    if (now - Number(item?.createdAt || 0) > ACTION_CONFIRM_TTL_MS) {
      pendingActionConfirmations.delete(id);
    }
  }
};

const isDeleteLikeAction = (action) => String(action?.name || "").toLowerCase().includes("delete");

const buildConfirmationRequestMessage = (actions) => {
  if (!Array.isArray(actions) || actions.length === 0) return "Konfirmasi aksi.";
  if (actions.length === 1) return `Konfirmasi aksi hapus untuk ${actions[0].name}.`;
  return `Konfirmasi ${actions.length} aksi hapus sekaligus.`;
};

const txTypeToCategoryType = (value) => {
  const raw = String(value || "").trim().toLowerCase();
  if (raw === "income") return "income";
  if (raw === "expense") return "expense";
  if (raw === "saving") return "saving";
  if (raw === "debt_payment") return "debt_payment";
  if (raw === "asset") return "asset";
  return null;
};

const getActionCategoryType = (action) => {
  if (!action || !action.args) return null;
  if (["createTransaction", "addTransaction", "updateTransaction"].includes(String(action.name || ""))) {
    return txTypeToCategoryType(action.args.type);
  }
  return null;
};

const getActionCategoryName = (action) => {
  if (!action || !action.args) return "";
  if (["createTransaction", "addTransaction", "updateTransaction"].includes(String(action.name || ""))) {
    return normalizeCategoryName(action.args.category || action.args.kategori || "");
  }
  return "";
};

const collectKnownCategoriesFromCurrentData = (currentData) => {
  const normalized = normalizeAccountingData(currentData || {});
  const map = {
    income: new Set(),
    expense: new Set(),
    saving: new Set(),
    debt_payment: new Set(),
    asset: new Set(),
  };

  for (const name of normalized.categories?.income || []) map.income.add(normalizeCategorySlug(name));
  for (const name of normalized.categories?.expenses || []) map.expense.add(normalizeCategorySlug(name));
  for (const name of normalized.categories?.assets || []) map.asset.add(normalizeCategorySlug(name));
  for (const name of normalized.categories?.debt_payment || normalized.categories?.debts || [])
    map.debt_payment.add(normalizeCategorySlug(name));
  for (const name of normalized.categories?.saving || []) map.saving.add(normalizeCategorySlug(name));
  for (const name of Object.keys(normalized.tabunganPlans || {})) map.saving.add(normalizeCategorySlug(name));

  return map;
};

const ensurePromptPayload = (payload) => {
  if (!payload || typeof payload !== "object") {
    throw new Error("Payload request tidak valid.");
  }
  const prompt = String(payload.prompt || "").trim();
  if (!prompt) {
    throw new Error("Prompt tidak boleh kosong.");
  }
  if (prompt.length > MAX_PROMPT_CHARS) {
    throw new Error(`Prompt terlalu panjang. Maksimal ${MAX_PROMPT_CHARS} karakter.`);
  }
  return prompt;
};

const logSecurityEvent = (event, payload = {}) => {
  console.log(
    "[security]",
    JSON.stringify({
      event,
      nodeEnv: NODE_ENV,
      ts: new Date().toISOString(),
      ...payload,
    })
  );
};

const persistSubscriptionToSupabase = async (params) => {
  if (!SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("SUPABASE_SERVICE_ROLE_KEY is missing.");
  }

  const postSubscription = (pathWithQuery, payload, prefer) =>
    fetch(`${SUPABASE_URL}/rest/v1/${pathWithQuery}`, {
      method: "POST",
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        "Content-Type": "application/json",
        Prefer: prefer,
      },
      body: JSON.stringify([payload]),
    });

  const fullPayload = {
    user_id: params.userId,
    plan: params.plan,
    status: params.status,
    product_id: params.productId,
    purchase_token: params.purchaseToken,
    google_order_id: params.googleOrderId || null,
    google_subscription_state: params.googleSubscriptionState || null,
    expires_at: params.expiresAt || null,
    paid_at: params.paidAt || null,
    raw_payload: params.rawPayload || null,
  };

  const legacyPayload = {
    user_id: params.userId,
    plan: params.plan,
    status: params.status,
    paid_at: params.paidAt || null,
  };

  let response = await postSubscription(
    "subscriptions?on_conflict=purchase_token",
    fullPayload,
    "resolution=merge-duplicates,return=representation"
  );
  let primaryError = "";

  if (!response.ok) {
    primaryError = await response.text();
    console.warn("[iap] full subscription upsert failed, retrying legacy payload:", primaryError);
    response = await postSubscription("subscriptions", legacyPayload, "return=representation");
  }

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Supabase subscription upsert failed (${response.status}): ${err || primaryError}`);
  }

  const data = await response.json();
  const saved = Array.isArray(data) ? data[0] : data;

  if (saved?.id && params.status === "active") {
    await fetch(
      `${SUPABASE_URL}/rest/v1/subscriptions?user_id=eq.${encodeURIComponent(params.userId)}&status=eq.active&id=neq.${encodeURIComponent(
        String(saved.id)
      )}`,
      {
        method: "PATCH",
        headers: {
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
          "Content-Type": "application/json",
          Prefer: "return=minimal",
        },
        body: JSON.stringify({ status: "canceled" }),
      }
    ).catch((error) => console.warn("Failed to cancel previous active subscriptions:", error));
  }

  return saved;
};
const SUPABASE_URL = process.env.SUPABASE_URL || "https://iygjnjkebhjwvhlmcnng.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const SUPABASE_PUBLISHABLE_KEY =
  process.env.SUPABASE_PUBLISHABLE_KEY ||
  process.env.SUPABASE_ANON_KEY ||
  "sb_publishable_EtyubbYluK0jhwk7wSypGw_rDEhRRIn";
const GOOGLE_PLAY_PACKAGE_NAME = process.env.GOOGLE_PLAY_PACKAGE_NAME || "";
const PLAN_PRODUCT_MAP = {
  skeptis: "skeptis_monthly",
  rajin: "rajin_monthly",
  freedoom: "freedoom_monthly",
};
const PLAN_DB_MAP = {
  skeptis: "starter",
  rajin: "personal",
  freedoom: "family_pro",
};
const NODE_ENV = String(process.env.NODE_ENV || "development").toLowerCase();
const IS_PRODUCTION = NODE_ENV === "production";
const TRUST_PROXY_RAW = String(process.env.TRUST_PROXY || "loopback").trim();
const TRUST_PROXY =
  TRUST_PROXY_RAW === "true"
    ? true
    : TRUST_PROXY_RAW === "false"
      ? false
      : Number.isFinite(Number(TRUST_PROXY_RAW)) && TRUST_PROXY_RAW !== ""
        ? Number(TRUST_PROXY_RAW)
        : TRUST_PROXY_RAW;
const RATE_LIMIT_WINDOW_MS = Math.max(10_000, Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000));
const RATE_LIMIT_CHAT_MAX = Math.max(1, Number(process.env.RATE_LIMIT_CHAT_MAX || 50));
const RATE_LIMIT_QUICK_MAX = Math.max(1, Number(process.env.RATE_LIMIT_QUICK_MAX || 40));
const RATE_LIMIT_IAP_MAX = Math.max(1, Number(process.env.RATE_LIMIT_IAP_MAX || 20));
const MAX_PROMPT_CHARS = Math.max(200, Number(process.env.MAX_PROMPT_CHARS || 6000));
const FINANCE_TABLE = "user_finance_snapshots";
const CATEGORY_TABLE = "user_finance_categories";
const ACCESS_OVERRIDE_TABLE = "user_access_overrides";
const PROMO_CODE_TABLE = "promo.codes";
const RECURRING_RULE_TABLE = "recurring_transaction_rules";
const RECURRING_RUN_TABLE = "recurring_transaction_runs";
const DEFAULT_TIMEZONE = "Asia/Jakarta";
const DEFAULT_ACCOUNT_NAME = "Cash / uang tunai";
const AGENT_ACTION_TOOLS = [
  {
    type: "function",
    function: {
      name: "AddAkunDompet",
      description: "Tambah akun dompet baru dengan saldo awal opsional.",
      parameters: {
        type: "object",
        properties: {
          name: { type: "string" },
          type: { type: "string" },
          saldo_awal: { type: "number" },
          startingBalance: { type: "number" },
        },
        required: ["name"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "createWallet",
      description: "Create a wallet/account with optional starting balance.",
      parameters: {
        type: "object",
        properties: {
          name: { type: "string" },
          type: { type: "string" },
          saldo_awal: { type: "number" },
          startingBalance: { type: "number" },
        },
        required: ["name"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "createTabungan",
      description: "Create a savings plan with name and target amount.",
      parameters: {
        type: "object",
        properties: {
          name: { type: "string" },
          target: { type: "number" },
        },
        required: ["name", "target"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "addTabungan",
      description: "Add savings amount into an existing plan.",
      parameters: {
        type: "object",
        properties: {
          name: { type: "string" },
          amount: { type: "number" },
          jumlah: { type: "number" },
          note: { type: "string" },
          catatan: { type: "string" },
          account: { type: "string" },
          date: { type: "string" },
          tanggal: { type: "string" },
        },
        required: ["name"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "createBudget",
      description: "Create a budget and define its limit.",
      parameters: {
        type: "object",
        properties: {
          name: { type: "string" },
          limit: { type: "number" },
        },
        required: ["name", "limit"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "updateBudget",
      description: "Update budget limit for an existing budget name.",
      parameters: {
        type: "object",
        properties: {
          name: { type: "string" },
          limit: { type: "number" },
        },
        required: ["name", "limit"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "addTransaction",
      description: "Record a financial transaction.",
      parameters: {
        type: "object",
        properties: {
          type: { type: "string", enum: ["income", "expense", "saving", "debt_payment", "asset"] },
          amount: { type: "number" },
          jumlah: { type: "number" },
          category: { type: "string" },
          kategori: { type: "string" },
          description: { type: "string" },
          catatan: { type: "string" },
          source: { type: "string" },
          sumber: { type: "string" },
          method: { type: "string" },
          metode: { type: "string" },
          account: { type: "string" },
          date: { type: "string" },
          tanggal: { type: "string" },
        },
        required: ["type"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "createGoal",
      description: "Create or update savings goal with target and current.",
      parameters: {
        type: "object",
        properties: {
          name: { type: "string" },
          target: { type: "number" },
          current: { type: "number" },
        },
        required: ["name", "target"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "createRecurringRule",
      description: "Create an automatic recurring transaction schedule.",
      parameters: {
        type: "object",
        properties: {
          amount: { type: "number" },
          category: { type: "string" },
          description: { type: "string" },
          account: { type: "string" },
          method: { type: "string" },
          frequency: { type: "string", enum: ["daily", "weekly", "monthly"] },
          interval: { type: "number" },
          run_time_local: { type: "string", description: "HH:mm local time" },
          weekdays: { type: "array", items: { type: "number" } },
          month_days: { type: "array", items: { type: "number" } },
          timezone_name: { type: "string" },
          start_date: { type: "string", description: "YYYY-MM-DD" },
          end_date: { type: "string", description: "YYYY-MM-DD" },
          is_active: { type: "boolean" },
        },
        required: ["amount", "category", "account", "frequency", "run_time_local"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "updateRecurringRule",
      description: "Update a recurring transaction schedule.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string" },
          amount: { type: "number" },
          category: { type: "string" },
          description: { type: "string" },
          account: { type: "string" },
          method: { type: "string" },
          frequency: { type: "string", enum: ["daily", "weekly", "monthly"] },
          interval: { type: "number" },
          run_time_local: { type: "string", description: "HH:mm local time" },
          weekdays: { type: "array", items: { type: "number" } },
          month_days: { type: "array", items: { type: "number" } },
          timezone_name: { type: "string" },
          start_date: { type: "string", description: "YYYY-MM-DD" },
          end_date: { type: "string", description: "YYYY-MM-DD" },
          is_active: { type: "boolean" },
        },
        required: ["id"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "pauseRecurringRule",
      description: "Pause or resume a recurring transaction schedule.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string" },
          is_active: { type: "boolean" },
        },
        required: ["id", "is_active"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "deleteRecurringRule",
      description: "Delete a recurring transaction schedule.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string" },
        },
        required: ["id"],
      },
    },
  },
];

const DEFAULT_ALLOWED_ORIGINS = [
  "http://localhost",
  "https://localhost",
  "http://localhost:3000",
  "https://localhost:3000",
  "capacitor://localhost",
  "ionic://localhost",
];
const ENV_ALLOWED_ORIGINS = String(process.env.CORS_ALLOWED_ORIGINS || "")
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean)
  .filter((v) => !v.includes("*"));
const ALLOWED_ORIGINS = Array.from(
  new Set([
    ...DEFAULT_ALLOWED_ORIGINS,
    ...ENV_ALLOWED_ORIGINS,
  ])
);
const LOCALHOST_ORIGIN_PROTOCOLS = new Set(["http:", "https:", "capacitor:", "ionic:"]);
if (String(process.env.CORS_ALLOWED_ORIGINS || "").includes("*")) {
  console.warn("[security] wildcard origin diabaikan dari CORS_ALLOWED_ORIGINS.");
}

const isAllowedOrigin = (origin) => {
  if (!origin) return true;
  if (ALLOWED_ORIGINS.includes(origin)) return true;

  try {
    const parsed = new URL(origin);
    return parsed.hostname === "localhost" && LOCALHOST_ORIGIN_PROTOCOLS.has(parsed.protocol);
  } catch {
    return false;
  }
};

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

const isFreeAccess = (accessPlan) =>
  !["premium", "paid", "subscribed"].includes(String(accessPlan || "").toLowerCase());

const resolveAccessModelPlan = (prompt, accessPlan) => {
  const plan = resolveModelPlan(prompt);
  if (!isFreeAccess(accessPlan)) return plan;
  return {
    ...plan,
    primary: OPENROUTER_MODEL_FREE,
    secondary: OPENROUTER_MODEL_FREE,
    primaryTimeout: OPENROUTER_TIMEOUT_FAST_MS,
    secondaryTimeout: OPENROUTER_TIMEOUT_FAST_MS,
  };
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
    tabunganPlans: currentData?.tabunganPlans || {},
    wallets: currentData?.wallets || {},
  },
  recurringRules: Array.isArray(currentData?.recurringRules)
    ? currentData.recurringRules.slice(0, 20).map((rule) => ({
      id: rule?.id,
      description: rule?.description,
      category: rule?.category,
      amount: rule?.amount,
      frequency: rule?.frequency,
      run_time_local: rule?.run_time_local,
      account_name: rule?.account_name,
      is_active: rule?.is_active,
    }))
    : [],
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

const buildActionSystemInstruction = (targetLanguage, compactData) => `You are a personal-finance action planner.
Return tool calls only for state-changing intent. Do not output JSON patch text.
Rules:
1) Use only available tools.
2) For budget progress/spent updates, never set spent directly. Use transactions for spending.
3) Every transaction should include an account wallet when possible.
4) Never fabricate money movement if funds are clearly insufficient; choose suitable wallet.
5) Prefer accurate Indonesian-friendly naming for budget, tabungan plan, and wallet.
6) Use AddAkunDompet when user asks to add/create wallet account.
7) For income transaction, prefer fields: tanggal, jumlah, kategori, sumber, catatan.
8) For expense transaction, prefer fields: tanggal, jumlah, kategori, metode, catatan.
9) If amount is missing, set default amount to 17000.
10) If date is missing, still send transaction and let app use local today's date.
11) You may call multiple tools when needed.
12) If user asks pure analysis/advice without mutation intent, do not call tools.
13) For recurring requests (tiap hari/minggu/bulan pada jam tertentu), use recurring tools.
14) Response language: ${targetLanguage}.

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
  assertOpenRouterKey();
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

const callOpenRouterActions = async (params) => {
  assertOpenRouterKey();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), params.timeoutMs);
  try {
    const response = await fetch(OPENROUTER_URL, {
      method: "POST",
      signal: controller.signal,
      headers: {
        Authorization: `Bearer ${OPENROUTER_API_KEY}`,
        "Content-Type": "application/json",
        "HTTP-Referer": params.referer || "http://localhost:3000",
        "X-Title": "Dompetku BackendOnly Actions",
      },
      body: JSON.stringify({
        model: params.model,
        temperature: 0,
        max_tokens: 320,
        messages: params.messages,
        tools: AGENT_ACTION_TOOLS,
        tool_choice: params.toolChoice,
      }),
    });
    if (!response.ok) {
      const err = await response.text();
      throw new Error(`OpenRouter Error ${response.status}: ${err}`);
    }
    const data = await response.json();
    const message = data?.choices?.[0]?.message || {};
    const toolCalls = Array.isArray(message?.tool_calls) ? message.tool_calls : [];
    const actions = toolCalls
      .map((item) => {
        const name = String(item?.function?.name || "");
        if (!name) return null;
        const argRaw = String(item?.function?.arguments || "{}");
        let args = {};
        try {
          args = JSON.parse(argRaw);
        } catch {
          args = {};
        }
        return { name, args };
      })
      .filter(Boolean);
    const assistantText = typeof message?.content === "string" ? message.content : "";
    return { actions, assistantText };
  } finally {
    clearTimeout(timeout);
  }
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

const parsePositiveInt = (v, fallback = 1) => {
  const num = Number(v);
  if (!Number.isFinite(num) || num <= 0) return fallback;
  return Math.max(1, Math.round(num));
};

const toYmd = (date) => date.toISOString().slice(0, 10);
const parseYmd = (value) => {
  if (!value) return null;
  const v = String(value).trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return null;
  return v;
};
const clampWeekdays = (arr) =>
  Array.from(
    new Set((Array.isArray(arr) ? arr : []).map((n) => Number(n)).filter((n) => Number.isInteger(n) && n >= 1 && n <= 7))
  ).sort((a, b) => a - b);
const clampMonthDays = (arr) =>
  Array.from(
    new Set((Array.isArray(arr) ? arr : []).map((n) => Number(n)).filter((n) => Number.isInteger(n) && n >= 1 && n <= 31))
  ).sort((a, b) => a - b);
const parseTimeHHMM = (value) => {
  const raw = String(value || "").trim();
  const match = raw.match(/^(\d{1,2}):(\d{2})$/);
  if (!match) return "12:00";
  const h = Math.min(23, Math.max(0, Number(match[1])));
  const m = Math.min(59, Math.max(0, Number(match[2])));
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
};
const getDefaultDateByTimezone = (timeZone) => {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(new Date());
  const get = (type) => parts.find((p) => p.type === type)?.value || "01";
  return `${get("year")}-${get("month")}-${get("day")}`;
};
const formatInTimeZoneParts = (date, timeZone) => {
  const dtf = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hour12: false,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    weekday: "short",
  });
  const parts = dtf.formatToParts(date);
  const read = (type) => parts.find((p) => p.type === type)?.value || "";
  const weekdayMap = { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 7 };
  return {
    year: Number(read("year")),
    month: Number(read("month")),
    day: Number(read("day")),
    hour: Number(read("hour")),
    minute: Number(read("minute")),
    second: Number(read("second")),
    weekday: weekdayMap[read("weekday")] || 1,
  };
};
const getTimezoneOffsetMinutes = (date, timeZone) => {
  const parts = formatInTimeZoneParts(date, timeZone);
  const asUtc = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second);
  return Math.round((asUtc - date.getTime()) / 60000);
};
const zonedLocalToUtc = (year, month, day, hour, minute, timeZone) => {
  let guess = Date.UTC(year, month - 1, day, hour, minute, 0);
  for (let i = 0; i < 3; i += 1) {
    const offset = getTimezoneOffsetMinutes(new Date(guess), timeZone);
    guess = Date.UTC(year, month - 1, day, hour, minute, 0) - offset * 60_000;
  }
  return new Date(guess);
};
const daySerial = (year, month, day) => Math.floor(Date.UTC(year, month - 1, day) / 86_400_000);
const mondaySerial = (year, month, day, weekday) => daySerial(year, month, day) - (weekday - 1);
const addDaysYmd = (year, month, day, plus) => {
  const d = new Date(Date.UTC(year, month - 1, day));
  d.setUTCDate(d.getUTCDate() + plus);
  return { year: d.getUTCFullYear(), month: d.getUTCMonth() + 1, day: d.getUTCDate() };
};
const monthsDiff = (aY, aM, bY, bM) => (aY - bY) * 12 + (aM - bM);

const normalizeRecurringRuleInput = (input, userId, now = new Date()) => {
  const timeZone = String(input.timezone_name || input.timezoneName || DEFAULT_TIMEZONE).trim() || DEFAULT_TIMEZONE;
  const frequencyRaw = String(input.frequency || "daily").toLowerCase();
  const frequency = frequencyRaw === "weekly" ? "weekly" : frequencyRaw === "monthly" ? "monthly" : "daily";
  const startDate = parseYmd(String(input.start_date || input.startDate || "")) || getDefaultDateByTimezone(timeZone);
  const endDate = parseYmd(String(input.end_date || input.endDate || ""));
  const normalized = {
    user_id: userId,
    is_active: input.is_active === false ? false : true,
    tx_type: "expense",
    amount: Math.max(1, Math.round(Number(input.amount || 0) || 0)),
    category: String(input.category || "Makan & Minum").trim() || "Makan & Minum",
    description: String(input.description || input.catatan || "").trim() || "Auto transaksi",
    method: String(input.method || input.metode || "Auto").trim() || "Auto",
    account_name: String(input.account_name || input.account || DEFAULT_ACCOUNT_NAME).trim() || DEFAULT_ACCOUNT_NAME,
    frequency,
    interval_value: parsePositiveInt(input.interval_value ?? input.interval ?? 1, 1),
    run_time_local: parseTimeHHMM(input.run_time_local || input.time || "12:00"),
    weekdays: clampWeekdays(input.weekdays),
    month_days: clampMonthDays(input.month_days),
    timezone_mode: String(input.timezone_mode || "device").toLowerCase() === "fixed" ? "fixed" : "device",
    timezone_name: timeZone,
    start_date: startDate,
    end_date: endDate,
  };
  if (normalized.amount <= 0) normalized.amount = 25_000;
  const nextRun = computeNextRunUtc({ ...normalized, id: "", next_run_at_utc: null }, now);
  return {
    ...normalized,
    next_run_at_utc: nextRun ? nextRun.toISOString() : null,
  };
};

const computeNextRunUtc = (rule, fromDate) => {
  const timeZone = rule.timezone_name || DEFAULT_TIMEZONE;
  const [hh, mm] = (rule.run_time_local || "12:00").split(":").map((v) => Number(v));
  const nowLocal = formatInTimeZoneParts(fromDate, timeZone);
  const startYmd = parseYmd(rule.start_date || "") || getDefaultDateByTimezone(timeZone);
  const [startY, startM, startD] = startYmd.split("-").map(Number);
  const endYmd = parseYmd(rule.end_date || "");
  const endParts = endYmd ? endYmd.split("-").map(Number) : null;
  const endSerial = endParts ? daySerial(endParts[0], endParts[1], endParts[2]) : null;
  const startLocalSerial = daySerial(startY, startM, startD);
  const cursorStart = Math.max(startLocalSerial, daySerial(nowLocal.year, nowLocal.month, nowLocal.day) - 1);
  const anchorLocal = formatInTimeZoneParts(zonedLocalToUtc(startY, startM, startD, 12, 0, timeZone), timeZone);
  const weeklyAnchorMonday = mondaySerial(startY, startM, startD, anchorLocal.weekday);
  const maxDaysScan = 370 * 3;

  const matchDay = (y, m, d, weekday) => {
    const serial = daySerial(y, m, d);
    if (serial < startLocalSerial) return false;
    if (endSerial !== null && serial > endSerial) return false;
    if (rule.frequency === "daily") {
      const diff = serial - startLocalSerial;
      return diff % Math.max(1, rule.interval_value || 1) === 0;
    }
    if (rule.frequency === "weekly") {
      const weekdays = rule.weekdays.length ? rule.weekdays : [1];
      if (!weekdays.includes(weekday)) return false;
      const weekIndex = Math.floor((serial - weeklyAnchorMonday) / 7);
      return weekIndex >= 0 && weekIndex % Math.max(1, rule.interval_value || 1) === 0;
    }
    const monthDays = rule.month_days.length ? rule.month_days : [startD];
    if (!monthDays.includes(d)) return false;
    const mdiff = monthsDiff(y, m, startY, startM);
    return mdiff >= 0 && mdiff % Math.max(1, rule.interval_value || 1) === 0;
  };

  for (let offset = 0; offset <= maxDaysScan; offset += 1) {
    const probe = addDaysYmd(startY, startM, startD, cursorStart - startLocalSerial + offset);
    const utcProbe = zonedLocalToUtc(probe.year, probe.month, probe.day, hh || 0, mm || 0, timeZone);
    const local = formatInTimeZoneParts(utcProbe, timeZone);
    if (!matchDay(local.year, local.month, local.day, local.weekday)) continue;
    const candidateUtc = zonedLocalToUtc(local.year, local.month, local.day, hh || 0, mm || 0, timeZone);
    if (candidateUtc.getTime() >= fromDate.getTime() - 1_000) return candidateUtc;
  }
  return null;
};

const syncSnapshotFinance = (accountingData, tx) => {
  const next = { ...(accountingData || {}) };
  next.transactions = Array.isArray(next.transactions) ? [...next.transactions, tx] : [tx];
  next.expenses = isObject(next.expenses) ? { ...next.expenses } : {};
  next.expenses[tx.category] = Number(next.expenses[tx.category] || 0) + Number(tx.amount || 0);
  next.wallets = isObject(next.wallets) ? { ...next.wallets } : {};
  if (!next.wallets[tx.account]) {
    next.wallets[tx.account] = { type: "Lainnya", startingBalance: 0, currentBalance: 0 };
  }
  next.wallets[tx.account] = {
    ...next.wallets[tx.account],
    currentBalance: Number(next.wallets[tx.account].currentBalance || 0) - Number(tx.amount || 0),
  };
  return next;
};

const supabaseRestFetch = async (pathWithQuery, init = {}) => {
  if (!SUPABASE_SERVICE_ROLE_KEY) throw new Error("SUPABASE_SERVICE_ROLE_KEY is missing.");
  const response = await fetch(`${SUPABASE_URL}/rest/v1/${pathWithQuery}`, {
    ...init,
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      ...(init.headers || {}),
    },
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Supabase REST ${response.status}: ${text}`);
  }
  if (response.status === 204) return null;
  return response.json();
};

const firstRow = (value) => (Array.isArray(value) ? value[0] : value);

const CATEGORY_TYPES = new Set(["income", "expense", "saving", "debt_payment", "asset"]);
const normalizeCategoryType = (value) => {
  const raw = String(value || "").trim().toLowerCase();
  if (raw === "income") return "income";
  if (raw === "expense" || raw === "expenses") return "expense";
  if (raw === "saving" || raw === "savings") return "saving";
  if (raw === "debt_payment" || raw === "debt" || raw === "debts") return "debt_payment";
  if (raw === "asset" || raw === "assets") return "asset";
  return null;
};
const normalizeCategoryName = (value) =>
  String(value || "")
    .trim()
    .replace(/\s+/g, " ")
    .replace(/[^\p{L}\p{N}\s&\-_]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
const normalizeCategorySlug = (value) =>
  normalizeCategoryName(value)
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();

const normalizeAccountingData = (input) => {
  const source = isObject(input) ? input : {};
  const categories = isObject(source.categories) ? source.categories : {};
  const normalized = {
    ...source,
    tabunganPlans: isObject(source.tabunganPlans) ? source.tabunganPlans : {},
    categories: {
      income: Array.isArray(categories.income) ? categories.income.map((v) => String(v || "").trim()).filter(Boolean) : [],
      expenses: Array.isArray(categories.expenses) ? categories.expenses.map((v) => String(v || "").trim()).filter(Boolean) : [],
      assets: Array.isArray(categories.assets) ? categories.assets.map((v) => String(v || "").trim()).filter(Boolean) : [],
      debts: Array.isArray(categories.debts) ? categories.debts.map((v) => String(v || "").trim()).filter(Boolean) : [],
      debt_payment: Array.isArray(categories.debt_payment)
        ? categories.debt_payment.map((v) => String(v || "").trim()).filter(Boolean)
        : Array.isArray(categories.debts)
          ? categories.debts.map((v) => String(v || "").trim()).filter(Boolean)
          : [],
      saving: Array.isArray(categories.saving) ? categories.saving.map((v) => String(v || "").trim()).filter(Boolean) : [],
    },
  };
  return normalized;
};

const sortUnique = (values) =>
  Array.from(new Set((Array.isArray(values) ? values : []).map((v) => String(v || "").trim()).filter(Boolean))).sort((a, b) =>
    a.localeCompare(b, "id")
  );

const collectCategorySeedsFromSnapshot = (accountingData) => {
  const data = normalizeAccountingData(accountingData || {});
  const seed = new Map();
  const add = (categoryType, name) => {
    if (!CATEGORY_TYPES.has(categoryType)) return;
    const normalizedName = normalizeCategoryName(name);
    if (!normalizedName) return;
    const key = `${categoryType}:${normalizeCategorySlug(normalizedName)}`;
    seed.set(key, { category_type: categoryType, name: normalizedName });
  };

  for (const name of data.categories.income) add("income", name);
  for (const name of data.categories.expenses) add("expense", name);
  for (const name of data.categories.assets) add("asset", name);
  for (const name of data.categories.debt_payment.length ? data.categories.debt_payment : data.categories.debts)
    add("debt_payment", name);
  for (const name of data.categories.saving) add("saving", name);
  for (const name of Object.keys(data.tabunganPlans || {})) add("saving", name);

  return Array.from(seed.values());
};

const readUserMasterCategories = async (userId, includeArchived = false) => {
  const archivedFilter = includeArchived ? "" : "&is_archived=eq.false";
  const rows = await supabaseRestFetch(
    `${CATEGORY_TABLE}?user_id=eq.${encodeURIComponent(
      userId
    )}${archivedFilter}&select=id,user_id,category_type,name,normalized_name,is_archived,source,created_at,updated_at&order=category_type.asc&order=name.asc`
  );
  return Array.isArray(rows) ? rows : [];
};

const upsertMasterCategories = async (userId, items = []) => {
  const deduped = new Map();
  for (const item of items) {
    const categoryType = normalizeCategoryType(item?.category_type || item?.type || item?.section);
    const name = normalizeCategoryName(item?.name);
    if (!categoryType || !name) continue;
    const normalizedName = normalizeCategorySlug(name);
    if (!normalizedName) continue;
    deduped.set(`${categoryType}:${normalizedName}`, {
      user_id: userId,
      category_type: categoryType,
      name,
      normalized_name: normalizedName,
      is_archived: false,
      source: String(item?.source || "manual").trim().toLowerCase() || "manual",
      updated_at: new Date().toISOString(),
    });
  }
  if (!deduped.size) return [];

  const rows = await supabaseRestFetch(
    `${CATEGORY_TABLE}?on_conflict=user_id,category_type,normalized_name&select=id,user_id,category_type,name,normalized_name,is_archived,source,created_at,updated_at`,
    {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=representation" },
      body: JSON.stringify(Array.from(deduped.values())),
    }
  );
  return Array.isArray(rows) ? rows : [];
};

const buildSnapshotCategoriesFromMaster = (rows, previous) => {
  const active = (Array.isArray(rows) ? rows : []).filter((item) => !item?.is_archived);
  const byType = {
    income: [],
    expense: [],
    saving: [],
    debt_payment: [],
    asset: [],
  };
  for (const row of active) {
    const categoryType = normalizeCategoryType(row.category_type);
    if (!categoryType) continue;
    byType[categoryType].push(row.name);
  }

  const debtList = sortUnique(byType.debt_payment);
  const prev = normalizeAccountingData(previous || {}).categories;
  return {
    income: sortUnique(byType.income.length ? byType.income : prev.income),
    expenses: sortUnique(byType.expense.length ? byType.expense : prev.expenses),
    assets: sortUnique(byType.asset.length ? byType.asset : prev.assets),
    debts: debtList.length ? debtList : sortUnique(prev.debts),
    debt_payment: debtList.length ? debtList : sortUnique(prev.debt_payment),
    saving: sortUnique(byType.saving.length ? byType.saving : prev.saving),
  };
};

const ensureCategoryMasterAndMirrorSnapshot = async (userId, rawAccountingData) => {
  const normalized = normalizeAccountingData(rawAccountingData || {});
  let rows = await readUserMasterCategories(userId, true);

  if (!rows.length) {
    const seeds = collectCategorySeedsFromSnapshot(normalized).map((item) => ({
      ...item,
      source: "seed",
    }));
    await upsertMasterCategories(userId, seeds);
    rows = await readUserMasterCategories(userId, true);
  }

  const categories = buildSnapshotCategoriesFromMaster(rows, normalized.categories);
  const mirrored = normalizeAccountingData({
    ...normalized,
    categories,
  });
  return { mirrored, rows };
};

const readUserBootstrapData = async (userId) => {
  const readOrNull = async (label, path) => {
    try {
      return firstRow(await supabaseRestFetch(path));
    } catch (error) {
      console.warn(`[bootstrap] ${label} unavailable:`, error);
      return null;
    }
  };

  const [profile, subscription, accessOverride] = await Promise.all([
    readOrNull("profile", `profiles?id=eq.${encodeURIComponent(userId)}&select=display_name,referral_code`),
    readOrNull(
      "subscription",
      `subscriptions?user_id=eq.${encodeURIComponent(
        userId
      )}&status=eq.active&select=plan,status,created_at&order=created_at.desc&limit=1`
    ),
    readOrNull(
      "access override",
      `${ACCESS_OVERRIDE_TABLE}?user_id=eq.${encodeURIComponent(
        userId
      )}&select=role,daily_task_limit,input_char_limit,note,updated_at`
    ),
  ]);

  return {
    profile: profile || null,
    subscription: subscription
      ? {
          plan: String(subscription.plan || ""),
          status: String(subscription.status || ""),
        }
      : null,
    accessOverride: accessOverride
      ? {
          role: accessOverride.role === "admin" ? "admin" : "user",
          daily_task_limit: Number(accessOverride.daily_task_limit) || 5,
          input_char_limit: Number(accessOverride.input_char_limit) || 50,
          note: accessOverride.note || null,
          updated_at: accessOverride.updated_at || null,
        }
      : null,
  };
};

const insertRecurringRun = async (payload, onConflict = "ignore") => {
  try {
    const data = await supabaseRestFetch(`${RECURRING_RUN_TABLE}?on_conflict=rule_id,scheduled_for_utc`, {
      method: "POST",
      headers: {
        Prefer:
          onConflict === "ignore"
            ? "resolution=ignore-duplicates,return=representation"
            : "return=representation",
      },
      body: JSON.stringify([payload]),
    });
    return Array.isArray(data) ? data[0] : data;
  } catch (error) {
    if (onConflict === "ignore" && /duplicate|23505/i.test(String(error?.message || ""))) return null;
    throw error;
  }
};

const updateRecurringRuleRow = async (ruleId, patch) => {
  const payload = { ...patch, updated_at: new Date().toISOString() };
  const data = await supabaseRestFetch(`${RECURRING_RULE_TABLE}?id=eq.${encodeURIComponent(ruleId)}&select=*`, {
    method: "PATCH",
    headers: { Prefer: "return=representation" },
    body: JSON.stringify(payload),
  });
  return Array.isArray(data) ? data[0] : data;
};

const buildRecurringTransaction = (rule, scheduledFor) => ({
  id: `rtx_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
  date: toYmd(scheduledFor),
  description: rule.description || `Auto ${rule.category}`,
  amount: Number(rule.amount) || 0,
  type: rule.tx_type || "expense",
  category: rule.category || "Lainnya",
  account: rule.account_name || DEFAULT_ACCOUNT_NAME,
  note: `[AUTO:${rule.id}] ${rule.description || ""}`.trim(),
  source: "recurring_rule",
  method: rule.method || "Auto",
});

const runRecurringRuleOnce = async (rule, now) => {
  const scheduledAt = new Date(rule.next_run_at_utc || now.toISOString());
  const runMarker = await insertRecurringRun(
    {
      rule_id: rule.id,
      user_id: rule.user_id,
      scheduled_for_utc: scheduledAt.toISOString(),
      executed_at_utc: now.toISOString(),
      status: "failed",
      reason: "processing",
    },
    "ignore"
  );
  if (!runMarker) return { processed: false, nextRun: null };

  try {
    const rows = await supabaseRestFetch(
      `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(rule.user_id)}&select=user_id,accounting_data,data_version`
    );
    const snapshot = Array.isArray(rows) ? rows[0] : rows;
    const accountingData = isObject(snapshot?.accounting_data) ? snapshot.accounting_data : {};
    const walletName = rule.account_name || DEFAULT_ACCOUNT_NAME;
    const walletBalance = Number(accountingData?.wallets?.[walletName]?.currentBalance || 0);
    const amount = Number(rule.amount) || 0;

    if (rule.tx_type !== "income" && walletBalance < amount) {
      await supabaseRestFetch(`${RECURRING_RUN_TABLE}?id=eq.${encodeURIComponent(String(runMarker.id))}`, {
        method: "PATCH",
        body: JSON.stringify({
          status: "skipped",
          reason: "skipped_insufficient_balance",
          executed_at_utc: new Date().toISOString(),
          snapshot_version: Number(snapshot?.data_version || 0),
        }),
      });
      const nextRun = computeNextRunUtc(rule, new Date(scheduledAt.getTime() + 60_000));
      return { processed: true, nextRun };
    }

    const tx = buildRecurringTransaction(rule, scheduledAt);
    const synced = syncSnapshotFinance(accountingData, tx);
    const nextVersion = Date.now();
    await supabaseRestFetch(`${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(rule.user_id)}`, {
      method: "PATCH",
      body: JSON.stringify({
        accounting_data: synced,
        data_version: nextVersion,
        updated_at: new Date().toISOString(),
      }),
    });
    await supabaseRestFetch(`${RECURRING_RUN_TABLE}?id=eq.${encodeURIComponent(String(runMarker.id))}`, {
      method: "PATCH",
      body: JSON.stringify({
        status: "success",
        reason: "executed",
        transaction_id: String(tx.id),
        snapshot_version: nextVersion,
        executed_at_utc: new Date().toISOString(),
      }),
    });
    const nextRun = computeNextRunUtc(rule, new Date(scheduledAt.getTime() + 60_000));
    return { processed: true, nextRun };
  } catch (error) {
    await supabaseRestFetch(`${RECURRING_RUN_TABLE}?id=eq.${encodeURIComponent(String(runMarker.id))}`, {
      method: "PATCH",
      body: JSON.stringify({
        status: "failed",
        reason: String(error?.message || "unknown_error").slice(0, 200),
        executed_at_utc: new Date().toISOString(),
      }),
    });
    throw error;
  }
};

const processRecurringRuleCatchup = async (rule, now) => {
  let currentRule = { ...rule };
  let safety = 0;
  while (
    currentRule.is_active &&
    currentRule.next_run_at_utc &&
    new Date(currentRule.next_run_at_utc).getTime() <= now.getTime() &&
    safety < 365
  ) {
    safety += 1;
    const { processed, nextRun } = await runRecurringRuleOnce(currentRule, now);
    if (!processed) break;
    currentRule.next_run_at_utc = nextRun ? nextRun.toISOString() : null;
    if (!currentRule.next_run_at_utc) {
      currentRule.is_active = false;
      break;
    }
  }
  await updateRecurringRuleRow(currentRule.id, {
    next_run_at_utc: currentRule.next_run_at_utc,
    is_active: currentRule.is_active,
  });
};

const runRecurringSchedulerTick = async () => {
  const now = new Date();
  const dueRules = await supabaseRestFetch(
    `${RECURRING_RULE_TABLE}?is_active=eq.true&next_run_at_utc=lte.${encodeURIComponent(now.toISOString())}&order=next_run_at_utc.asc&limit=200`
  );
  const rows = Array.isArray(dueRules) ? dueRules : [];
  for (const raw of rows) {
    try {
      await processRecurringRuleCatchup(raw, now);
    } catch (error) {
      console.error("[recurring] tick rule failed", raw?.id, error);
    }
  }
};

app.set("trust proxy", TRUST_PROXY);
app.use(helmet());
app.use(express.json({ limit: "10mb" }));
app.use(
  cors({
    origin(origin, callback) {
      if (isAllowedOrigin(origin)) return callback(null, true);
      return callback(new Error(`Origin not allowed: ${origin}`));
    },
  })
);

const makeLimiter = (max, scope) =>
  rateLimit({
    windowMs: RATE_LIMIT_WINDOW_MS,
    max,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { error: "Terlalu banyak request. Coba lagi sebentar." },
    handler: (req, res) => {
      logSecurityEvent("rate_limit_block", {
        scope,
        ip: req.ip,
        path: req.path,
      });
      return res.status(429).json({ error: "Terlalu banyak request. Coba lagi sebentar." });
    },
  });

app.use("/api/chat", makeLimiter(RATE_LIMIT_CHAT_MAX, "chat"));
app.use("/api/chat/stream", makeLimiter(RATE_LIMIT_CHAT_MAX, "chat_stream"));
app.use("/api/quick-suggestions", makeLimiter(RATE_LIMIT_QUICK_MAX, "quick_suggestions"));
app.use("/api/iap", makeLimiter(RATE_LIMIT_IAP_MAX, "iap"));

app.get("/health", (_req, res) => {
  const base = {
    ok: true,
    app: "Dompetku-BackendOnly",
    env: NODE_ENV,
  };
  if (IS_PRODUCTION) {
    return res.json(base);
  }
  return res.json({
    ...base,
    openrouterKeyLoaded: hasOpenRouterKey(),
    models: {
      fast: OPENROUTER_MODEL_FAST,
      heavy: OPENROUTER_MODEL_HEAVY,
      free: OPENROUTER_MODEL_FREE,
      report: OPENROUTER_MODEL_REPORT_RECOMMENDATION,
    },
  });
});

app.get("/api/health/ai", (_req, res) => {
  res.json({
    ok: true,
    hasOpenRouterKey: hasOpenRouterKey(),
    modelFree: OPENROUTER_MODEL_FREE,
    modelReport: OPENROUTER_MODEL_REPORT_RECOMMENDATION,
    modelQuickSuggest: OPENROUTER_MODEL_QUICK_SUGGEST,
    nodeEnv: process.env.NODE_ENV || "development",
  });
});

app.get("/api/me/bootstrap", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    return res.json(await readUserBootstrapData(userId));
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to load user bootstrap data." });
  }
});

app.patch("/api/me/profile", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const displayName = String(req.body?.display_name || "").trim().slice(0, 80);
    if (!displayName) return res.status(400).json({ error: "display_name wajib diisi." });

    const rows = await supabaseRestFetch("profiles?on_conflict=id&select=display_name,referral_code", {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=representation" },
      body: JSON.stringify([{ id: userId, display_name: displayName }]),
    });
    return res.json({ profile: firstRow(rows) || null });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to update profile." });
  }
});

app.get("/api/accounting-snapshot", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const rows = await supabaseRestFetch(
      `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(userId)}&select=accounting_data,data_version,updated_at`
    );
    const snapshot = firstRow(rows);
    const { mirrored } = await ensureCategoryMasterAndMirrorSnapshot(userId, snapshot?.accounting_data || {});
    await supabaseRestFetch(`${FINANCE_TABLE}?on_conflict=user_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify([
        {
          user_id: userId,
          accounting_data: mirrored,
          data_version: Number(snapshot?.data_version || Date.now()),
          updated_at: new Date().toISOString(),
        },
      ]),
    });
    return res.json({
      accountingData: mirrored || null,
      dataVersion: snapshot?.data_version || null,
      updatedAt: snapshot?.updated_at || null,
    });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to read accounting snapshot." });
  }
});

app.put("/api/accounting-snapshot", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const accountingData = normalizeAccountingData(req.body?.accountingData || req.body?.accounting_data || {});
    await upsertMasterCategories(
      userId,
      collectCategorySeedsFromSnapshot(accountingData).map((item) => ({ ...item, source: "snapshot_sync" }))
    );
    const { mirrored } = await ensureCategoryMasterAndMirrorSnapshot(userId, accountingData);
    const dataVersion = Date.now();
    await supabaseRestFetch(`${FINANCE_TABLE}?on_conflict=user_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify([
        {
          user_id: userId,
          accounting_data: mirrored,
          data_version: dataVersion,
          updated_at: new Date().toISOString(),
        },
      ]),
    });
    return res.json({ ok: true, dataVersion });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to save accounting snapshot." });
  }
});

app.get("/api/categories", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const includeArchived = String(req.query.include_archived || "false").toLowerCase() === "true";
    let categories = await readUserMasterCategories(userId, includeArchived);
    if (!categories.length) {
      const snapshotRows = await supabaseRestFetch(
        `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(userId)}&select=accounting_data`
      );
      const snapshot = firstRow(snapshotRows);
      await ensureCategoryMasterAndMirrorSnapshot(userId, snapshot?.accounting_data || {});
      categories = await readUserMasterCategories(userId, includeArchived);
    }
    return res.json({ categories });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to list categories." });
  }
});

app.post("/api/categories", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const categoryType = normalizeCategoryType(req.body?.category_type || req.body?.type || req.body?.section);
    const name = normalizeCategoryName(req.body?.name);
    if (!categoryType || !name) {
      return res.status(400).json({ error: "category_type dan name wajib diisi." });
    }

    const rows = await upsertMasterCategories(userId, [
      {
        category_type: categoryType,
        name,
        source: req.body?.source || "manual",
      },
    ]);

    const snapshotRows = await supabaseRestFetch(
      `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(userId)}&select=accounting_data,data_version`
    );
    const snapshot = firstRow(snapshotRows);
    const { mirrored } = await ensureCategoryMasterAndMirrorSnapshot(userId, snapshot?.accounting_data || {});
    await supabaseRestFetch(`${FINANCE_TABLE}?on_conflict=user_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify([
        {
          user_id: userId,
          accounting_data: mirrored,
          data_version: Date.now(),
          updated_at: new Date().toISOString(),
        },
      ]),
    });

    return res.json({ ok: true, category: firstRow(rows) || null });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to create category." });
  }
});

app.patch("/api/categories/:id", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ error: "Category id wajib diisi." });

    const categoryType = normalizeCategoryType(req.body?.category_type || req.body?.type || req.body?.section);
    const name = normalizeCategoryName(req.body?.name);
    if (!categoryType && !name) {
      return res.status(400).json({ error: "Minimal name atau category_type wajib diisi." });
    }

    const patch = { updated_at: new Date().toISOString() };
    if (categoryType) patch.category_type = categoryType;
    if (name) {
      patch.name = name;
      patch.normalized_name = normalizeCategorySlug(name);
    }

    const rows = await supabaseRestFetch(
      `${CATEGORY_TABLE}?id=eq.${encodeURIComponent(id)}&user_id=eq.${encodeURIComponent(userId)}&select=id,user_id,category_type,name,normalized_name,is_archived,source,created_at,updated_at`,
      {
        method: "PATCH",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify(patch),
      }
    );
    const category = firstRow(rows);
    if (!category) return res.status(404).json({ error: "Category tidak ditemukan." });

    const snapshotRows = await supabaseRestFetch(
      `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(userId)}&select=accounting_data,data_version`
    );
    const snapshot = firstRow(snapshotRows);
    const { mirrored } = await ensureCategoryMasterAndMirrorSnapshot(userId, snapshot?.accounting_data || {});
    await supabaseRestFetch(`${FINANCE_TABLE}?on_conflict=user_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify([
        {
          user_id: userId,
          accounting_data: mirrored,
          data_version: Date.now(),
          updated_at: new Date().toISOString(),
        },
      ]),
    });

    return res.json({ ok: true, category });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to update category." });
  }
});

app.post("/api/categories/:id/archive", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ error: "Category id wajib diisi." });

    const rows = await supabaseRestFetch(
      `${CATEGORY_TABLE}?id=eq.${encodeURIComponent(id)}&user_id=eq.${encodeURIComponent(userId)}&select=id,user_id,category_type,name,normalized_name,is_archived,source,created_at,updated_at`,
      {
        method: "PATCH",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({ is_archived: true, updated_at: new Date().toISOString() }),
      }
    );
    const category = firstRow(rows);
    if (!category) return res.status(404).json({ error: "Category tidak ditemukan." });

    const snapshotRows = await supabaseRestFetch(
      `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(userId)}&select=accounting_data,data_version`
    );
    const snapshot = firstRow(snapshotRows);
    const { mirrored } = await ensureCategoryMasterAndMirrorSnapshot(userId, snapshot?.accounting_data || {});
    await supabaseRestFetch(`${FINANCE_TABLE}?on_conflict=user_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify([
        {
          user_id: userId,
          accounting_data: mirrored,
          data_version: Date.now(),
          updated_at: new Date().toISOString(),
        },
      ]),
    });

    return res.json({ ok: true, category });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to archive category." });
  }
});

app.post("/api/categories/:id/unarchive", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ error: "Category id wajib diisi." });

    const rows = await supabaseRestFetch(
      `${CATEGORY_TABLE}?id=eq.${encodeURIComponent(id)}&user_id=eq.${encodeURIComponent(userId)}&select=id,user_id,category_type,name,normalized_name,is_archived,source,created_at,updated_at`,
      {
        method: "PATCH",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({ is_archived: false, updated_at: new Date().toISOString() }),
      }
    );
    const category = firstRow(rows);
    if (!category) return res.status(404).json({ error: "Category tidak ditemukan." });

    const snapshotRows = await supabaseRestFetch(
      `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(userId)}&select=accounting_data,data_version`
    );
    const snapshot = firstRow(snapshotRows);
    const { mirrored } = await ensureCategoryMasterAndMirrorSnapshot(userId, snapshot?.accounting_data || {});
    await supabaseRestFetch(`${FINANCE_TABLE}?on_conflict=user_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify([
        {
          user_id: userId,
          accounting_data: mirrored,
          data_version: Date.now(),
          updated_at: new Date().toISOString(),
        },
      ]),
    });

    return res.json({ ok: true, category });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to unarchive category." });
  }
});

app.get("/api/recurring-rules", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const rows = await supabaseRestFetch(
      `${RECURRING_RULE_TABLE}?user_id=eq.${encodeURIComponent(userId)}&order=created_at.desc`
    );
    return res.json({ rules: Array.isArray(rows) ? rows : [] });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to list recurring rules." });
  }
});

app.post("/api/recurring-rules", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const input = normalizeRecurringRuleInput(req.body || {}, userId, new Date());
    const rows = await supabaseRestFetch(`${RECURRING_RULE_TABLE}?select=*`, {
      method: "POST",
      headers: { Prefer: "return=representation" },
      body: JSON.stringify([input]),
    });
    const row = Array.isArray(rows) ? rows[0] : rows;
    return res.json({ rule: row });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to create recurring rule." });
  }
});

app.patch("/api/recurring-rules/:id", requireSupabaseUser, async (req, res) => {
  try {
    const ruleId = String(req.params.id || "").trim();
    const userId = req.authUser.id;
    if (!ruleId) return res.status(400).json({ error: "rule id is required." });
    const currentRows = await supabaseRestFetch(
      `${RECURRING_RULE_TABLE}?id=eq.${encodeURIComponent(ruleId)}&user_id=eq.${encodeURIComponent(userId)}&select=*`
    );
    const current = Array.isArray(currentRows) ? currentRows[0] : currentRows;
    if (!current) return res.status(404).json({ error: "Recurring rule not found." });

    const mergedInput = {
      ...current,
      ...req.body,
    };
    const next = normalizeRecurringRuleInput(mergedInput, userId, new Date());
    const updated = await updateRecurringRuleRow(ruleId, { ...next, user_id: userId });
    return res.json({ rule: updated });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to update recurring rule." });
  }
});

app.delete("/api/recurring-rules/:id", requireSupabaseUser, async (req, res) => {
  try {
    const ruleId = String(req.params.id || "").trim();
    const userId = req.authUser.id;
    if (!ruleId) return res.status(400).json({ error: "rule id is required." });
    await supabaseRestFetch(
      `${RECURRING_RULE_TABLE}?id=eq.${encodeURIComponent(ruleId)}&user_id=eq.${encodeURIComponent(userId)}`,
      {
        method: "DELETE",
        headers: { Prefer: "return=minimal" },
      }
    );
    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to delete recurring rule." });
  }
});

app.get("/api/recurring-runs", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const limit = Math.min(200, Math.max(1, Number(req.query.limit || 50)));
    const rows = await supabaseRestFetch(
      `${RECURRING_RUN_TABLE}?user_id=eq.${encodeURIComponent(userId)}&order=created_at.desc&limit=${limit}`
    );
    return res.json({ runs: Array.isArray(rows) ? rows : [] });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to list recurring runs." });
  }
});

app.post("/api/recurring-rules/:id/sync-timezone", requireSupabaseUser, async (req, res) => {
  try {
    const ruleId = String(req.params.id || "").trim();
    const userId = req.authUser.id;
    const timezoneName = String(req.body?.timezone_name || "").trim();
    if (!ruleId || !timezoneName) {
      return res.status(400).json({ error: "rule id and timezone_name are required." });
    }
    const currentRows = await supabaseRestFetch(
      `${RECURRING_RULE_TABLE}?id=eq.${encodeURIComponent(ruleId)}&user_id=eq.${encodeURIComponent(userId)}&select=*`
    );
    const current = Array.isArray(currentRows) ? currentRows[0] : currentRows;
    if (!current) return res.status(404).json({ error: "Recurring rule not found." });
    const merged = {
      ...current,
      timezone_name: timezoneName,
    };
    const normalized = normalizeRecurringRuleInput(merged, userId, new Date());
    const updated = await updateRecurringRuleRow(ruleId, {
      timezone_name: timezoneName,
      timezone_mode: "device",
      next_run_at_utc: normalized.next_run_at_utc,
    });
    return res.json({ rule: updated });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to sync timezone." });
  }
});

app.post("/api/agent/actions", async (req, res) => {
  const started = Date.now();
  let safePrompt = "";
  try {
    const { currentData, language, accessPlan } = req.body || {};
    try {
      safePrompt = ensurePromptPayload(req.body || {});
    } catch (error) {
      return res.status(400).json({
        ok: false,
        error: error?.message || "Payload tidak valid.",
        actions: [],
        assistantText: "",
      });
    }

    const targetLanguage = String(language || "Indonesian");
    const { primary, secondary, primaryTimeout, secondaryTimeout } =
      resolveAccessModelPlan(safePrompt, accessPlan);
    logAiRoute("/api/agent/actions", {
      accessPlan: accessPlan || "free",
      inputChars: safePrompt.length,
      model: primary,
    });
    const compactData = buildCompactData(currentData || {});
    const actionSystem = buildActionSystemInstruction(targetLanguage, compactData);
    const messages = [
      { role: "system", content: actionSystem },
      { role: "user", content: safePrompt },
    ];

    let usedModel = primary;
    let fallbackUsed = false;
    let retryForced = false;
    let result = await callOpenRouterActions({
      model: primary,
      timeoutMs: primaryTimeout,
      messages,
      referer: req.headers.referer,
      toolChoice: "auto",
    });

    if (!result.actions.length) {
      retryForced = true;
      result = await callOpenRouterActions({
        model: primary,
        timeoutMs: primaryTimeout,
        messages,
        referer: req.headers.referer,
        toolChoice: "required",
      });
    }

    if (!result.actions.length) {
      fallbackUsed = true;
      usedModel = secondary;
      result = await callOpenRouterActions({
        model: secondary,
        timeoutMs: secondaryTimeout,
        messages,
        referer: req.headers.referer,
        toolChoice: "required",
      });
    }

    if (!result.actions.length) {
      return res.status(422).json({
        ok: false,
        actions: [],
        confirmationRequests: [],
        assistantText: "",
        error:
          "Aksi belum terbaca jelas. Coba tulis lebih spesifik, contoh: 'Tambah tabungan mobil 500rb' atau 'Catat makan 25rb'.",
        metadata: {
          processing_mode: "ai_actions",
          model_used: usedModel,
          fallback_used: fallbackUsed,
          retry_forced_tool_choice: retryForced,
          total_ms: Date.now() - started,
        },
      });
    }

    cleanupExpiredActionConfirmations();
    const knownCategoryMap = collectKnownCategoriesFromCurrentData(currentData || {});
    const directActions = [];
    const deleteActions = [];
    const unknownCategoryConfirmChains = [];
    const unknownCategoryKeys = new Set();

    for (const action of result.actions) {
      if (isDeleteLikeAction(action)) {
        deleteActions.push(action);
        continue;
      }

      const categoryType = getActionCategoryType(action);
      const categoryName = getActionCategoryName(action);
      if (
        categoryType &&
        categoryName &&
        categoryType !== "saving" &&
        !knownCategoryMap[categoryType].has(normalizeCategorySlug(categoryName))
      ) {
        const key = `${categoryType}:${normalizeCategorySlug(categoryName)}`;
        if (!unknownCategoryKeys.has(key)) {
          unknownCategoryKeys.add(key);
          unknownCategoryConfirmChains.push({
            categoryType,
            categoryName,
            actions: [
              {
                name: "createCategory",
                args: {
                  category_type: categoryType,
                  name: categoryName,
                  source: "ai",
                  section: categoryType === "income" ? "income" : categoryType === "expense" ? "expenses" : categoryType === "asset" ? "assets" : categoryType === "debt_payment" ? "debts" : "saving",
                },
              },
              action,
            ],
          });
        } else {
          const chain = unknownCategoryConfirmChains.find(
            (item) => item.categoryType === categoryType && normalizeCategorySlug(item.categoryName) === normalizeCategorySlug(categoryName)
          );
          if (chain) chain.actions.push(action);
        }
        continue;
      }

      directActions.push(action);
    }

    const confirmationRequests = [];
    if (deleteActions.length) {
      const confirmationId = `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
      pendingActionConfirmations.set(confirmationId, {
        id: confirmationId,
        createdAt: Date.now(),
        actions: deleteActions,
        summary: buildConfirmationRequestMessage(deleteActions),
      });
      confirmationRequests.push({
        id: confirmationId,
        title: "Konfirmasi Aksi Hapus",
        message: buildConfirmationRequestMessage(deleteActions),
        actions: deleteActions,
        kind: "delete",
      });
    }

    for (const chain of unknownCategoryConfirmChains) {
      const confirmationId = `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
      const message = `Kategori "${chain.categoryName}" (${chain.categoryType}) belum ada. Konfirmasi untuk membuat kategori baru lalu lanjutkan transaksi.`;
      pendingActionConfirmations.set(confirmationId, {
        id: confirmationId,
        createdAt: Date.now(),
        actions: chain.actions,
        summary: message,
      });
      confirmationRequests.push({
        id: confirmationId,
        title: "Konfirmasi Kategori Baru",
        message,
        actions: chain.actions,
        kind: "unknown_category",
      });
    }

    return res.json({
      ok: true,
      actions: directActions,
      confirmationRequests,
      assistantText:
        result.assistantText?.trim() ||
        (confirmationRequests.length
          ? "Perintah siap. Ada aksi yang menunggu konfirmasi kamu."
          : "Siap, perubahan data keuangan sudah saya susun."),
      metadata: {
        processing_mode: "ai_actions",
        model_used: usedModel,
        fallback_used: fallbackUsed,
        retry_forced_tool_choice: retryForced,
        total_ms: Date.now() - started,
      },
    });
  } catch (error) {
    console.error("Agent Actions Error:", error);
    return res.status(500).json({
      ok: false,
      actions: [],
      assistantText: "",
      error: error?.message || "Agent action request failed.",
    });
  }
});

app.post("/api/agent/actions/confirm", async (req, res) => {
  try {
    const { confirmationId, currentData } = req.body || {};
    const id = String(confirmationId || "").trim();
    if (!id) {
      return res.status(400).json({ ok: false, error: "confirmationId wajib diisi." });
    }
    cleanupExpiredActionConfirmations();
    const pending = pendingActionConfirmations.get(id);
    if (!pending) {
      return res.status(404).json({ ok: false, error: "Konfirmasi tidak ditemukan atau kadaluarsa." });
    }
    pendingActionConfirmations.delete(id);

    return res.json({
      ok: true,
      actions: Array.isArray(pending.actions) ? pending.actions : [],
      recurringActions: Array.isArray(pending.actions) ? pending.actions : [],
      updatedData: normalizeAccountingData(currentData || {}),
      notices: [],
      actionSummaries: [],
      metrics: null,
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      error: error?.message || "Gagal memproses konfirmasi aksi.",
    });
  }
});

app.post("/api/agent/actions/cancel", async (req, res) => {
  try {
    const { confirmationId } = req.body || {};
    const id = String(confirmationId || "").trim();
    if (!id) {
      return res.status(400).json({ ok: false, error: "confirmationId wajib diisi." });
    }
    pendingActionConfirmations.delete(id);
    return res.json({ ok: true, cancelled: true });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      error: error?.message || "Gagal membatalkan konfirmasi aksi.",
    });
  }
});

app.post("/api/chat", async (req, res) => {
  const started = Date.now();
  let prompt = "";
  try {
    const { currentData, language, accessPlan } = req.body || {};
    try {
      prompt = ensurePromptPayload(req.body || {});
    } catch (error) {
      return res.status(400).json({ error: error?.message || "Payload tidak valid." });
    }
    const targetLanguage = language || "Indonesian";
    const { primary, secondary, primaryTimeout, secondaryTimeout, maxTokens } =
      resolveAccessModelPlan(prompt || "", accessPlan);
    const intent = classifyIntent(prompt || "");
    logAiRoute("/api/chat", {
      accessPlan: accessPlan || "free",
      intent,
      inputChars: String(prompt || "").length,
      model: primary,
    });
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

  let prompt = "";
  try {
    const { currentData, language, accessPlan } = req.body || {};
    try {
      prompt = ensurePromptPayload(req.body || {});
    } catch (error) {
      res.status(400).json({ error: error?.message || "Payload tidak valid." });
      return;
    }
    const targetLanguage = language || "Indonesian";
    const { primary, secondary, primaryTimeout, secondaryTimeout, maxTokens } =
      resolveAccessModelPlan(prompt || "", accessPlan);
    const intent = classifyIntent(prompt || "");
    logAiRoute("/api/chat/stream", {
      accessPlan: accessPlan || "free",
      intent,
      inputChars: String(prompt || "").length,
      model: primary,
    });
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
    const { text, language, accessPlan } = req.body || {};
    const query = String(text || "").trim();
    if (!query) return res.json({ suggestions: [] });
    if (query.length > MAX_PROMPT_CHARS) {
      return res.status(400).json({ error: `Input terlalu panjang. Maksimal ${MAX_PROMPT_CHARS} karakter.` });
    }

    const prompt = `User is typing this request: "${query}".
Generate exactly 3 short quick suggestions for a personal finance assistant app.
Rules:
- Language: ${language || "Indonesian"}
- Each suggestion max 10 words
- Practical and directly actionable
- No numbering, no markdown, no explanation
- Return valid JSON object only: {"suggestions":["...","...","..."]}`;
    const usedModel = isFreeAccess(accessPlan) ? OPENROUTER_MODEL_FREE : OPENROUTER_MODEL_QUICK_SUGGEST;
    logAiRoute("/api/quick-suggestions", {
      accessPlan: accessPlan || "free",
      inputChars: query.length,
      model: usedModel,
    });

    const result = await callOpenRouterText({
      model: usedModel,
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

app.post("/api/report/recommendations", async (req, res) => {
  const started = Date.now();
  try {
    const { currentData, language } = req.body || {};
    const targetLanguage = String(language || "Indonesian");
    if (!currentData || typeof currentData !== "object") {
      return res.status(400).json({ error: "Missing currentData." });
    }

    logAiRoute("/api/report/recommendations", {
      model: OPENROUTER_MODEL_REPORT_RECOMMENDATION,
    });

    const result = await callOpenRouterText({
      model: OPENROUTER_MODEL_REPORT_RECOMMENDATION,
      timeoutMs: 18000,
      maxTokens: 220,
      referer: req.headers.referer,
      messages: [
        {
          role: "user",
          content: buildReportRecommendationPrompt(targetLanguage, currentData),
        },
      ],
    });

    const aiResult = parseReportAiResult(result.text);
    if (!aiResult.recommendations.length && aiResult.healthScore === null) {
      throw new Error("No report AI result returned");
    }

    return res.json({
      recommendations: aiResult.recommendations,
      healthScore: aiResult.healthScore,
      healthStatus: aiResult.healthStatus,
      metadata: {
        processing_mode: "report_recommendation",
        model_used: OPENROUTER_MODEL_REPORT_RECOMMENDATION,
        ttft_ms: result.ttftMs,
        total_ms: Date.now() - started,
      },
    });
  } catch (error) {
    console.error("Report Recommendation Error:", error);
    return res.status(503).json({ error: error?.message || "Report recommendations unavailable" });
  }
});

app.get("/api/promocodes/public", async (req, res) => {
  try {
    const code = String(req.query.code || "").trim().toUpperCase();
    if (!SUPABASE_SERVICE_ROLE_KEY) {
      return res.status(503).json({ error: "PromoCode service belum dikonfigurasi di server." });
    }
    const codeFilter = code ? `&code=eq.${encodeURIComponent(code)}` : "";
    const rows = await supabaseRestFetch(
      `${PROMO_CODE_TABLE}?is_active=eq.true${codeFilter}&select=code,reward_type,plan_code,duration_days,daily_task_limit,input_char_limit,note,starts_at,expires_at,quota_total,quota_used&order=code.asc`
    );
    const nowIso = new Date().toISOString();
    const items = (Array.isArray(rows) ? rows : []).map((row) => ({
      code: String(row.code || "").toUpperCase(),
      reward_type: String(row.reward_type || "plan"),
      plan_code: String(row.plan_code || "") || null,
      duration_days: Number(row.duration_days || 0) || 0,
      daily_task_limit: Number(row.daily_task_limit || 0) || 0,
      input_char_limit: Number(row.input_char_limit || 0) || 0,
      starts_at: row.starts_at || null,
      expires_at: row.expires_at || null,
      quota_total: Number(row.quota_total || 0) || 0,
      quota_used: Number(row.quota_used || 0) || 0,
      is_redeemable:
        (!row.starts_at || String(row.starts_at) <= nowIso) &&
        (!row.expires_at || String(row.expires_at) >= nowIso) &&
        (Number(row.quota_total || 0) <= 0 || Number(row.quota_used || 0) < Number(row.quota_total || 0)),
      note: row.note || null,
    }));
    return res.json({ rewards: items });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to read promocodes." });
  }
});

app.post("/api/promocodes/redeem", requireSupabaseUser, async (req, res) => {
  try {
    if (!SUPABASE_SERVICE_ROLE_KEY) {
      return res.status(503).json({ error: "PromoCode service belum dikonfigurasi di server." });
    }
    const userId = req.authUser?.id;
    const code = String(req.body?.code || "").trim().toUpperCase();
    if (!code) return res.status(400).json({ error: "Kode PromoCode wajib diisi.", errorCode: "PROMO_NOT_FOUND" });

    const result = await supabaseRestFetch("rpc/redeem_promocode", {
      method: "POST",
      body: JSON.stringify({ p_user_id: userId, p_code: code }),
    });
    const payload = firstRow(result) || result;
    return res.json({
      ok: true,
      alreadyRedeemed: Boolean(payload?.already_redeemed),
      code,
      appliedReward: payload?.applied_reward || null,
      subscription: payload?.subscription || null,
      accessOverride: payload?.access_override || null,
      message: String(payload?.message || "PromoCode berhasil diterapkan."),
    });
  } catch (error) {
    const message = String(error?.message || "");
    const errorCode = mapPromoError(message);
    if (errorCode === "PROMO_ALREADY_REDEEMED") {
      return res.json({
        ok: true,
        alreadyRedeemed: true,
        code: String(req.body?.code || "").trim().toUpperCase(),
        appliedReward: null,
        subscription: null,
        accessOverride: null,
        message: "PromoCode sudah pernah dipakai di akun ini.",
        errorCode,
      });
    }
    const status = errorCode === "PROMO_NOT_FOUND" ? 404 : 400;
    return res.status(status).json({
      ok: false,
      error: message || "Failed to redeem promocode.",
      errorCode,
    });
  }
});

app.post("/api/iap/google/verify", async (req, res) => {
  try {
    const { userId, plan, productId, purchaseToken } = req.body || {};
    const requestedUserId = String(userId || "").trim();
    const safePlan = String(plan || "").trim().toLowerCase();
    const safeProductId = String(productId || "").trim();
    const safeToken = String(purchaseToken || "").trim();
    const accessToken = getBearerTokenFromRequest(req);

    if (!safePlan || !safeProductId || !safeToken) {
      return res.status(400).json({ error: "Missing required fields: plan, productId, purchaseToken." });
    }
    if (!SUPABASE_SERVICE_ROLE_KEY) {
      return res.status(503).json({ error: "Server subscription writer is not configured." });
    }
    if (!accessToken) {
      return res.status(401).json({ error: "Login session tidak ditemukan untuk verifikasi pembelian." });
    }

    const expectedProductId = PLAN_PRODUCT_MAP[safePlan];
    const dbPlan = PLAN_DB_MAP[safePlan];
    if (!expectedProductId) {
      return res.status(400).json({ error: `Unknown plan: ${safePlan}` });
    }
    if (safeProductId !== expectedProductId) {
      return res.status(400).json({ error: `Invalid product for plan ${safePlan}` });
    }

    const authUser = await verifySupabaseUserAccessToken(accessToken);
    if (!authUser?.id) {
      return res.status(401).json({ error: "Session Supabase tidak valid." });
    }
    if (requestedUserId && requestedUserId !== authUser.id) {
      return res.status(403).json({ error: "Session user tidak cocok dengan user pembelian." });
    }
    const safeUserId = String(authUser.id);

    let verifyPayload = null;
    let normalizedStatus = "trialing";
    let paidAt = null;
    let expiresAt = null;
    let googleOrderId = null;
    let googleSubscriptionState = null;

    if (safeToken.startsWith("demo_")) {
      if (process.env.NODE_ENV === "production") {
        return res.status(400).json({ error: "Demo purchase token tidak boleh dipakai di production." });
      }
      verifyPayload = { mode: "demo", subscriptionState: "SUBSCRIPTION_STATE_ACTIVE" };
      normalizedStatus = "active";
      paidAt = new Date().toISOString();
    } else {
      verifyPayload = await verifyGoogleSubscription(safeToken);
      const playState = String(verifyPayload?.subscriptionState || "");
      googleSubscriptionState = playState || null;
      googleOrderId = String(verifyPayload?.latestOrderId || verifyPayload?.lineItems?.[0]?.latestSuccessfulOrderId || "") || null;
      expiresAt = String(verifyPayload?.lineItems?.[0]?.expiryTime || "") || null;
      if (playState === "SUBSCRIPTION_STATE_ACTIVE") normalizedStatus = "active";
      if (playState === "SUBSCRIPTION_STATE_IN_GRACE_PERIOD") normalizedStatus = "past_due";
      if (playState === "SUBSCRIPTION_STATE_ON_HOLD") normalizedStatus = "past_due";
      if (playState === "SUBSCRIPTION_STATE_CANCELED" || playState === "SUBSCRIPTION_STATE_EXPIRED") {
        normalizedStatus = "canceled";
      }
      if (normalizedStatus === "active") paidAt = new Date().toISOString();

      const actualProductId = verifyPayload?.lineItems?.[0]?.productId;
      if (actualProductId && actualProductId !== safeProductId) {
        return res.status(400).json({ error: "Purchase token does not match selected product." });
      }
    }

    const savedSubscription = await persistSubscriptionToSupabase({
      userId: safeUserId,
      plan: dbPlan || safePlan,
      status: normalizedStatus,
      productId: safeProductId,
      purchaseToken: safeToken,
      googleOrderId,
      googleSubscriptionState,
      expiresAt,
      paidAt,
      rawPayload: verifyPayload,
    });

    return res.json({
      ok: true,
      message:
        normalizedStatus === "active"
          ? "Pembelian berhasil diverifikasi dan subscription aktif."
          : "Pembelian terverifikasi, menunggu status aktif dari Google Play.",
      subscription: {
        plan: dbPlan || safePlan,
        productId: safeProductId,
        status: normalizedStatus,
        expiresAt,
        paidAt,
      },
      savedSubscription,
      verifyPayload,
    });
  } catch (error) {
    console.error("IAP verify error:", error);
    return res.status(500).json({ error: error?.message || "IAP verification failed." });
  }
});

if (SUPABASE_SERVICE_ROLE_KEY) {
  const runTick = async () => {
    try {
      await runRecurringSchedulerTick();
    } catch (error) {
      console.error("[recurring] scheduler tick failed:", error);
    }
  };
  void runTick();
  setInterval(runTick, 60_000);
} else {
  console.warn("[recurring] scheduler disabled: SUPABASE_SERVICE_ROLE_KEY missing.");
}

app.listen(PORT, "0.0.0.0", () => {
  console.log(`BackendOnly running on http://0.0.0.0:${PORT}`);
});
