const path = require("path");

require("dotenv").config({ path: path.join(__dirname, ".env") });

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const { JWT } = require("google-auth-library");
const fs = require("fs");

const app = express();
const pendingActionConfirmations = new Map();
const pendingActionSelections = new Map();
const ACTION_CONFIRM_TTL_MS = 10 * 60 * 1000;
const NOTIFICATION_MESSAGES_FILE = path.join(__dirname, "notification-messages.txt");
const DEFAULT_NOTIFICATION_MESSAGES = {
  morning: ["Selamat pagi! Yuk cek dompet hari ini sebelum mulai aktivitas."],
  afternoon: ["Sore ini sempatkan lihat pengeluaranmu, biar budget tetap aman."],
  night: ["Sebelum tidur, cek lagi transaksi hari ini supaya catatan tetap rapi."],
};

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

const resolveFirebaseServiceAccount = () => {
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    const parsed = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
    return {
      projectId: parsed.project_id || "",
      clientEmail: parsed.client_email || "",
      privateKey: String(parsed.private_key || "").replace(/\\n/g, "\n"),
    };
  }
  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    const parsed = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    return {
      projectId: parsed.project_id || "",
      clientEmail: parsed.client_email || "",
      privateKey: String(parsed.private_key || "").replace(/\\n/g, "\n"),
    };
  }
  return {
    projectId: process.env.FIREBASE_PROJECT_ID || "",
    clientEmail: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || "",
    privateKey: String(process.env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
  };
};

const getFirebaseMessagingAccessToken = async () => {
  const { clientEmail, privateKey } = resolveFirebaseServiceAccount();
  if (!clientEmail || !privateKey) {
    throw new Error("Firebase service account credentials are missing.");
  }
  const client = new JWT({
    email: clientEmail,
    key: privateKey,
    scopes: ["https://www.googleapis.com/auth/firebase.messaging"],
  });
  const token = await client.getAccessToken();
  if (!token.token) throw new Error("Failed to obtain Firebase Messaging access token.");
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

const getUserIdFromRequest = async (req) => {
  const token = getBearerTokenFromRequest(req);
  if (!token) return null;
  try {
    const authUser = await verifySupabaseUserAccessToken(token);
    return authUser?.id || null;
  } catch (err) {
    return null;
  }
};

const savePendingAction = async (id, userId, type, data) => {
  if (userId) {
    try {
      await supabaseRestFetch('agent_pending_confirmations', {
        method: 'POST',
        body: JSON.stringify({
          id,
          user_id: userId,
          type,
          data,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
      });
      return;
    } catch (dbErr) {
      console.error("[savePendingAction] Database save failed, falling back to memory:", dbErr);
    }
  }
  // Fallback to memory
  if (type === 'confirmation') {
    pendingActionConfirmations.set(id, {
      id,
      createdAt: Date.now(),
      ...data
    });
  } else if (type === 'selection') {
    pendingActionSelections.set(id, {
      id,
      createdAt: Date.now(),
      ...data
    });
  }
};

const getPendingAction = async (id, userId, type) => {
  if (userId) {
    try {
      const rows = await supabaseRestFetch(
        `agent_pending_confirmations?id=eq.${encodeURIComponent(id)}&type=eq.${encodeURIComponent(type)}&select=*`
      ).catch(() => null);
      const row = firstRow(rows);
      if (row) {
        return {
          id: row.id,
          createdAt: new Date(row.created_at).getTime(),
          ...row.data
        };
      }
    } catch (dbErr) {
      console.error("[getPendingAction] Database lookup failed:", dbErr);
    }
  }
  // Fallback to memory
  if (type === 'confirmation') {
    return pendingActionConfirmations.get(id);
  } else if (type === 'selection') {
    return pendingActionSelections.get(id);
  }
  return null;
};

const deletePendingAction = async (id, userId, type) => {
  if (userId) {
    try {
      await supabaseRestFetch(
        `agent_pending_confirmations?id=eq.${encodeURIComponent(id)}&type=eq.${encodeURIComponent(type)}`,
        { method: 'DELETE' }
      ).catch(() => null);
    } catch (dbErr) {
      console.error("[deletePendingAction] Database delete failed:", dbErr);
    }
  }
  // Always delete from memory to be clean
  if (type === 'confirmation') {
    pendingActionConfirmations.delete(id);
  } else if (type === 'selection') {
    pendingActionSelections.delete(id);
  }
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
  for (const [id, item] of pendingActionSelections.entries()) {
    if (now - Number(item?.createdAt || 0) > ACTION_CONFIRM_TTL_MS) {
      pendingActionSelections.delete(id);
    }
  }

  // Database cleanup in background (fire-and-forget)
  const cutoff = new Date(Date.now() - ACTION_CONFIRM_TTL_MS).toISOString();
  supabaseRestFetch(
    `agent_pending_confirmations?created_at=lt.${encodeURIComponent(cutoff)}`,
    { method: "DELETE" }
  ).catch((err) => {
    console.error("[cleanupExpiredActionConfirmations] DB cleanup error:", err?.message || err);
  });
};

const ACTION_CONFIRMATION_EXEMPTIONS = new Set(["calculateFinanceMetrics"]);
const AGENT_ALLOWED_ACTIONS = new Set([
  "createTabungan",
  "createTabunganPlan",
  "updateTabunganPlan",
  "deleteTabunganPlan",
  "addTabungan",
  "createGoal",
  "createBudget",
  "updateBudget",
  "deleteBudget",
  "addTransaction",
  "createTransaction",
  "updateTransaction",
  "deleteTransaction",
  "bulkUpdateTransactions",
  "bulkDeleteTransactions",
]);
const INVESTMENT_HINT_KEYWORDS = [
  "bitcoin",
  "btc",
  "crypto",
  "kripto",
  "saham",
  "emas",
  "reksa",
  "invest",
  "investasi",
];

const formatAmountForSummary = (value) => {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount <= 0) return "";
  return amount.toLocaleString("id-ID");
};

const summarizeActionForConfirmation = (action) => {
  const name = String(action?.name || "").trim();
  const args = isObject(action?.args) ? action.args : {};
  const amount = formatAmountForSummary(args.amount || args.jumlah || args.limit || args.target || args.current);
  const category = String(args.category || args.kategori || args.name || args.old_name || "").trim();

  if (!name) return "Aksi perubahan data";
  if (name === "addTransaction" || name === "createTransaction") {
    const type = String(args.type || "").trim();
    const wallet = String(args.account || "").trim();
    const parts = [`Catat transaksi ${type || "baru"}`];
    if (amount) parts.push(`Rp${amount}`);
    if (category) parts.push(`kategori ${category}`);
    if (wallet) parts.push(`dompet ${wallet}`);
    return parts.join(" ");
  }
  if (name === "createTabungan" || name === "createTabunganPlan" || name === "createGoal" || name === "updateTabunganPlan") {
    const parts = [name === "createGoal" || name === "updateTabunganPlan" ? "Perbarui tabungan" : "Buat tabungan"];
    if (category) parts.push(`"${category}"`);
    if (amount) parts.push(`target Rp${amount}`);
    return parts.join(" ");
  }
  if (name === "addTabungan") {
    const parts = ["Tambah tabungan"];
    if (category) parts.push(`"${category}"`);
    if (amount) parts.push(`Rp${amount}`);
    return parts.join(" ");
  }
  if (name === "createWallet" || name === "AddAkunDompet") {
    const parts = ["Buat dompet"];
    if (category) parts.push(`"${category}"`);
    if (amount) parts.push(`saldo awal Rp${amount}`);
    return parts.join(" ");
  }
  if (name === "updateWallet") {
    return `Perbarui dompet "${category || "dompet"}"`;
  }
  if (name === "deleteWallet") {
    return `Hapus dompet "${category || "dompet"}"`;
  }
  if (name === "createBudget" || name === "updateBudget") {
    const parts = [name === "createBudget" ? "Buat budget" : "Perbarui budget"];
    if (category) parts.push(`"${category}"`);
    if (amount) parts.push(`limit Rp${amount}`);
    return parts.join(" ");
  }
  if (name === "deleteBudget") {
    return `Hapus budget "${category || "budget"}"`;
  }
  if (name === "createCategory") {
    return `Buat kategori "${category || "baru"}"`;
  }
  if (name === "renameCategory") {
    const nextName = String(args.new_name || args.to || "").trim();
    if (category && nextName) return `Ubah kategori "${category}" menjadi "${nextName}"`;
    return "Ubah kategori";
  }
  if (name === "deleteCategory") {
    return `Hapus kategori "${category || "kategori"}"`;
  }
  if (name === "updateTransaction") {
    return `Perbarui transaksi "${String(args.id || "").trim() || "terpilih"}"`;
  }
  if (name === "deleteTransaction") {
    return `Hapus transaksi "${String(args.id || "").trim() || "terpilih"}"`;
  }
  if (name === "bulkUpdateTransactions") return "Perbarui banyak transaksi";
  if (name === "bulkDeleteTransactions") return "Hapus banyak transaksi";
  if (name === "createRecurringRule") return "Buat jadwal transaksi otomatis";
  if (name === "updateRecurringRule") return "Perbarui jadwal transaksi otomatis";
  if (name === "pauseRecurringRule") return "Jeda jadwal transaksi otomatis";
  if (name === "deleteRecurringRule") return "Hapus jadwal transaksi otomatis";
  return name;
};

const buildConfirmationRequestMessage = (actions) => {
  if (!Array.isArray(actions) || actions.length === 0) return "Konfirmasi perubahan data.";
  const preview = actions.slice(0, 4).map((action) => summarizeActionForConfirmation(action)).filter(Boolean);
  const extra = actions.length > preview.length ? `, dan ${actions.length - preview.length} aksi lain` : "";
  return `Ada ${actions.length} perubahan data yang menunggu konfirmasi: ${preview.join("; ")}${extra}.`;
};

const isConfirmationRequiredAction = (action) => {
  const name = String(action?.name || "").trim();
  if (!name) return false;
  return !ACTION_CONFIRMATION_EXEMPTIONS.has(name);
};

const isAllowedAgentAction = (action) => AGENT_ALLOWED_ACTIONS.has(String(action?.name || "").trim());

const isInvestmentPrompt = (prompt) => {
  const text = normalizePromptText(prompt);
  if (!text) return false;
  return INVESTMENT_HINT_KEYWORDS.some((keyword) => text.includes(keyword));
};

const findRelatedEntityCandidates = (currentData, prompt) => {
  const text = normalizePromptText(prompt);
  if (!text) return [];
  const candidates = [];
  const tabunganPlans = isObject(currentData?.tabunganPlans) ? currentData.tabunganPlans : {};
  const budgets = isObject(currentData?.budgets) ? currentData.budgets : {};

  for (const name of Object.keys(tabunganPlans)) {
    const slug = normalizePromptText(name);
    if (slug && (text.includes(slug) || slug.split(" ").some((part) => part.length > 2 && text.includes(part)))) {
      candidates.push({ type: "tabungan", name });
    }
  }
  for (const name of Object.keys(budgets)) {
    const slug = normalizePromptText(name);
    if (slug && (text.includes(slug) || slug.split(" ").some((part) => part.length > 2 && text.includes(part)))) {
      candidates.push({ type: "budget", name });
    }
  }
  return candidates.slice(0, 3);
};

const getFirstTransactionAmount = (actions) => {
  for (const action of Array.isArray(actions) ? actions : []) {
    if (!["addTransaction", "createTransaction"].includes(String(action?.name || ""))) continue;
    const amount = toNumber(action?.args?.amount || action?.args?.jumlah);
    if (amount > 0) return amount;
  }
  return 0;
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
const isPlaceholderEnvValue = (value) => /\byour[-_]/i.test(String(value || ""));
const normalizeEnvValue = (value) => {
  const next = String(value || "").trim();
  return next && !isPlaceholderEnvValue(next) ? next : "";
};
const SUPABASE_URL =
  normalizeEnvValue(process.env.SUPABASE_URL) ||
  normalizeEnvValue(process.env.VITE_SUPABASE_URL) ||
  "https://iygjnjkebhjwvhlmcnng.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = normalizeEnvValue(process.env.SUPABASE_SERVICE_ROLE_KEY);
const SUPABASE_PUBLISHABLE_KEY =
  normalizeEnvValue(process.env.SUPABASE_PUBLISHABLE_KEY) ||
  normalizeEnvValue(process.env.SUPABASE_ANON_KEY) ||
  normalizeEnvValue(process.env.VITE_SUPABASE_ANON_KEY) ||
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
const AUTO_TRANSACTION_PLAN_CODES = new Set(["personal", "family_pro", "rajin", "freedoom", "freedom"]);
const AUTO_TRANSACTION_ACCESS_ERROR = "Fitur Transaksi Otomatis tersedia untuk paket Rajin dan Freedom/Family Pro.";
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
const SUBSCRIPTION_TABLE = "subscriptions";
const DEVICE_TOKEN_TABLE = "user_device_tokens";
const DEFAULT_TIMEZONE = "Asia/Jakarta";
const DEFAULT_ACCOUNT_NAME = "Total Keuangan";
const TRANSACTION_TOOL_PARAMETERS = {
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
    classification_reason: { type: "string" },
    confidence: { type: "number", minimum: 0, maximum: 1 },
  },
  required: ["type"],
};
const AGENT_ACTION_TOOLS_RAW = [
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
      name: "updateTabunganPlan",
      description: "Update target/current tabungan plan.",
      parameters: {
        type: "object",
        properties: {
          name: { type: "string" },
          target: { type: "number" },
          current: { type: "number" },
          note: { type: "string" },
        },
        required: ["name"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "deleteTabunganPlan",
      description: "Delete tabungan plan by name.",
      parameters: {
        type: "object",
        properties: {
          name: { type: "string" },
          reassign_to: { type: "string" },
        },
        required: ["name"],
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
      name: "deleteBudget",
      description: "Delete budget by name.",
      parameters: {
        type: "object",
        properties: {
          name: { type: "string" },
        },
        required: ["name"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "addTransaction",
      description:
        "Record a financial transaction. Use type=asset for buying/adding assets or investments such as Bitcoin, crypto, stocks, gold, mutual funds, property, vehicles, or valuables; this is a cash outflow but should increase assets, not expenses.",
      parameters: TRANSACTION_TOOL_PARAMETERS,
    },
  },
  {
    type: "function",
    function: {
      name: "createTransaction",
      description:
        "Alias for addTransaction. Record a financial transaction with the same type classification rules, including type=asset for buying/adding wealth or investments.",
      parameters: TRANSACTION_TOOL_PARAMETERS,
    },
  },
  {
    type: "function",
    function: {
      name: "updateTransaction",
      description: "Update an existing transaction.",
      parameters: {
        ...TRANSACTION_TOOL_PARAMETERS,
        properties: {
          ...TRANSACTION_TOOL_PARAMETERS.properties,
          id: { type: "string" },
        },
        required: ["id"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "deleteTransaction",
      description: "Delete transaction by id.",
      parameters: {
        type: "object",
        properties: {
          id: { type: "string" },
        },
        required: ["id"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "bulkUpdateTransactions",
      description: "Bulk update existing transactions.",
      parameters: {
        type: "object",
        properties: {
          items: {
            type: "array",
            items: {
              type: "object",
            },
          },
        },
        required: ["items"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "bulkDeleteTransactions",
      description: "Bulk delete transactions by ids.",
      parameters: {
        type: "object",
        properties: {
          ids: {
            type: "array",
            items: { type: "string" },
          },
        },
        required: ["ids"],
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
const AGENT_ACTION_TOOLS = AGENT_ACTION_TOOLS_RAW.filter((tool) =>
  AGENT_ALLOWED_ACTIONS.has(String(tool?.function?.name || ""))
);

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

const parseNotificationMessages = (rawText) => {
  const next = {
    morning: [],
    afternoon: [],
    night: [],
  };
  let currentSection = null;
  for (const rawLine of String(rawText || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const sectionMatch = line.match(/^\[(morning|afternoon|night)\]$/i);
    if (sectionMatch) {
      currentSection = sectionMatch[1].toLowerCase();
      continue;
    }
    if (currentSection) next[currentSection].push(line);
  }
  return {
    morning: next.morning.length ? next.morning : DEFAULT_NOTIFICATION_MESSAGES.morning,
    afternoon: next.afternoon.length ? next.afternoon : DEFAULT_NOTIFICATION_MESSAGES.afternoon,
    night: next.night.length ? next.night : DEFAULT_NOTIFICATION_MESSAGES.night,
  };
};

const readNotificationMessages = async () => {
  try {
    const raw = await fs.promises.readFile(NOTIFICATION_MESSAGES_FILE, "utf8");
    return parseNotificationMessages(raw);
  } catch (error) {
    console.warn("[notification-messages] using defaults:", error?.message);
    return DEFAULT_NOTIFICATION_MESSAGES;
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

const DEFAULT_PAID_FAST_MODEL = "deepseek/deepseek-v4-flash";
const DEFAULT_PAID_HEAVY_MODEL = "deepseek/deepseek-v4-flash";
const DEFAULT_FREE_MODEL = "deepseek/deepseek-v4-flash:free";
const warnedModelConfigLabels = new Set();

const isFreeModelId = (model) => String(model || "").includes(":free");

const sanitizeModelId = (model, fallback) => {
  const raw = String(model || "").trim();
  return raw || fallback;
};

const sanitizePaidModelId = (model, fallback, label) => {
  const safe = sanitizeModelId(model, fallback);
  if (isFreeModelId(safe)) {
    if (!warnedModelConfigLabels.has(label)) {
      warnedModelConfigLabels.add(label);
      console.warn(`[ai-model] ${label} is configured as free (${safe}). Using paid fallback (${fallback}).`);
    }
    return fallback;
  }
  return safe;
};

const uniqueModelChain = (models) => {
  const out = [];
  const seen = new Set();
  for (const item of Array.isArray(models) ? models : []) {
    const model = String(item || "").trim();
    if (!model || seen.has(model)) continue;
    seen.add(model);
    out.push(model);
  }
  return out;
};

const resolveAiRouteModelPolicy = ({ route, prompt, accessPlan }) => {
  const base = resolveModelPlan(prompt || "");
  const planTier = isFreeAccess(accessPlan) ? "free" : "paid";
  const freeModel = sanitizeModelId(OPENROUTER_MODEL_FREE, DEFAULT_FREE_MODEL);

  if (planTier === "free") {
    return {
      planTier,
      intent: base.intent,
      primaryModel: freeModel,
      fallbackModels: [],
      modelFallbackChain: [freeModel],
      primaryTimeout: OPENROUTER_TIMEOUT_FAST_MS,
      secondaryTimeout: OPENROUTER_TIMEOUT_FAST_MS,
      maxTokens: base.maxTokens,
    };
  }

  const fastModel = sanitizePaidModelId(OPENROUTER_MODEL_FAST, DEFAULT_PAID_FAST_MODEL, "OPENROUTER_MODEL_FAST");
  const heavyModel = sanitizePaidModelId(OPENROUTER_MODEL_HEAVY, DEFAULT_PAID_HEAVY_MODEL, "OPENROUTER_MODEL_HEAVY");

  let primaryModel = base.intent === "simple" ? fastModel : heavyModel;
  let paidFallbackModel = base.intent === "simple" ? heavyModel : fastModel;

  if (route === "quick_suggestions") {
    primaryModel = fastModel;
    paidFallbackModel = heavyModel;
  }
  if (route === "report_recommendations") {
    primaryModel = heavyModel;
    paidFallbackModel = fastModel;
  }

  const modelFallbackChain = uniqueModelChain([primaryModel, paidFallbackModel, freeModel]);

  return {
    planTier,
    intent: base.intent,
    primaryModel: modelFallbackChain[0],
    fallbackModels: modelFallbackChain.slice(1),
    modelFallbackChain,
    primaryTimeout: base.primaryTimeout,
    secondaryTimeout: base.secondaryTimeout,
    maxTokens: base.maxTokens,
  };
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

const isFreeAccess = (accessPlan) => {
  const plan = String(accessPlan || "").toLowerCase().trim();
  // "premium", "paid", "subscribed" = paid subscription; "admin" = admin override
  return !["premium", "paid", "subscribed", "admin"].includes(plan);
};

const resolveAccessModelPlan = (prompt, accessPlan) => {
  const policy = resolveAiRouteModelPolicy({ route: "chat", prompt, accessPlan });
  return {
    intent: policy.intent,
    primary: policy.primaryModel,
    secondary: policy.fallbackModels[0] || policy.primaryModel,
    primaryTimeout: policy.primaryTimeout,
    secondaryTimeout: policy.secondaryTimeout,
    maxTokens: policy.maxTokens,
  };
};

// Startup guard rails for paid model configuration.
sanitizePaidModelId(OPENROUTER_MODEL_FAST, DEFAULT_PAID_FAST_MODEL, "OPENROUTER_MODEL_FAST");
sanitizePaidModelId(OPENROUTER_MODEL_HEAVY, DEFAULT_PAID_HEAVY_MODEL, "OPENROUTER_MODEL_HEAVY");

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
3) You are allowed to mutate only: budget, tabungan (savings plans), and transactions.
4) Never use wallet tools, category tools, or recurring tools.
5) Every transaction must use "Total Keuangan" as the account/wallet.
6) Never fabricate money movement if funds are clearly insufficient.
7) For income transaction, prefer fields: tanggal, jumlah, kategori, sumber, catatan.
8) For expense transaction, prefer fields: tanggal, jumlah, kategori, metode, catatan.
9) Classify transaction type by semantic money purpose, not by memorized keywords. Ask: after this transaction, did the user receive money, consume/spend money, move money into a savings goal, pay a liability, or convert cash into wealth/asset?
   - income: user receives money, e.g. salary, bonus, freelance, sale proceeds, dividends/profit received.
   - expense: money is consumed as a cost, e.g. food, transport, bills, shopping, fees, admin costs, losses.
   - saving: money moved into an app-style savings target/plan, e.g. emergency fund, vacation, house goal.
   - debt_payment: money pays debt/installments, e.g. loan, credit card, paylater, cicilan.
   - asset: user buys/adds wealth or an investment instrument. This includes regional language, slang, mixed English/Indonesian, and typos when the meaning is converting cash into harta/aset.
10) Do not classify by object name alone. "beli emas" is asset, "jual emas" is income, "fee beli emas" is expense, "rugi trading" is expense. Investment purchases reduce wallet cash but increase assets/harta.
11) Required examples:
   - "invest bitcoin 100 ribu" => addTransaction({ type: "asset", amount: 100000, category: "Bitcoin", description: "Investasi Bitcoin" })
   - "beli emas 1 juta" => addTransaction({ type: "asset", amount: 1000000, category: "Emas" })
   - "dapat gaji 5 juta" => addTransaction({ type: "income", amount: 5000000, category: "Gaji" })
   - "makan 25 ribu" => addTransaction({ type: "expense", amount: 25000, category: "Makan & Minum" })
12) If amount is missing, set default amount to 17000.
13) If date is missing, still send transaction and let app use local today's date.
14) You may call multiple tools when needed.
15) If user asks pure analysis/advice without mutation intent, do not call tools.
16) If user asks for advice/consultation/analysis, do not mutate data and do not call tools.
17) If user asks features outside allowed mutate scope (wallet/category/recurring), explain briefly and stay in advisor mode.
18) For transaction tools, include classification_reason and confidence when possible. Keep reason short.
19) Response language: ${targetLanguage}.

Compact context:
${JSON.stringify(compactData)}`;

const normalizePromptText = (value) =>
  String(value || "")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s&\-_]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();

const ASSET_PURCHASE_KEYWORDS = [
  "invest",
  "investasi",
  "bitcoin",
  "btc",
  "crypto",
  "saham",
  "emas",
];
const NON_ASSET_PURCHASE_KEYWORDS = [
  "jual",
  "dijual",
  "terjual",
  "hasil jual",
  "profit",
  "untung",
  "dividen",
  "rugi",
  "kerugian",
  "fee",
  "biaya admin",
  "admin",
  "pajak",
];

const inferAssetCategoryFromPrompt = (prompt) => {
  const text = normalizePromptText(prompt);
  if (/\b(bitcoin|btc)\b/.test(text)) return "Bitcoin";
  if (/\b(crypto|kripto)\b/.test(text)) return "Crypto";
  if (/\bsaham\b/.test(text)) return "Saham";
  if (/\bemas\b/.test(text)) return "Emas";
  if (/\breksa dana\b|\breksadana\b/.test(text)) return "Reksa Dana";
  if (/\bproperti\b/.test(text)) return "Properti";
  if (/\bkendaraan\b/.test(text)) return "Kendaraan";
  if (/\bbarang berharga\b/.test(text)) return "Barang Berharga";
  return "Investasi";
};

const shouldCoerceExpenseToAsset = (prompt) => {
  const text = normalizePromptText(prompt);
  if (!text) return false;
  if (NON_ASSET_PURCHASE_KEYWORDS.some((keyword) => text.includes(keyword))) return false;
  const hasAssetKeyword = ASSET_PURCHASE_KEYWORDS.some((keyword) => text.includes(keyword));
  const hasPurchaseIntent = /\b(beli|buy|invest|investasi|top up|topup|masuk(in)?|tambah)\b/.test(text);
  return hasAssetKeyword && hasPurchaseIntent;
};

const applyMinimalAssetKeywordFallback = (actions, prompt) => {
  if (!shouldCoerceExpenseToAsset(prompt)) return actions;
  const category = inferAssetCategoryFromPrompt(prompt);
  return (Array.isArray(actions) ? actions : []).map((action) => {
    if (!["addTransaction", "createTransaction"].includes(String(action?.name || ""))) return action;
    const args = { ...(action.args || {}) };
    const txType = String(args.type || "").trim().toLowerCase();
    if (txType !== "expense") return action;
    const currentCategory = String(args.category || args.kategori || "").trim();
    args.type = "asset";
    if (!currentCategory || ["lainnya", "pengeluaran", "belanja", "investasi"].includes(currentCategory.toLowerCase())) {
      args.category = category;
      delete args.kategori;
    }
    if (!args.description && !args.catatan) {
      args.description = `Investasi ${category}`;
    }
    delete args.method;
    delete args.metode;
    return { ...action, args };
  });
};

const stripJsonFence = (value) =>
  String(value || "")
    .trim()
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();

const parseJsonObject = (value) => {
  const raw = stripJsonFence(value);
  try {
    return JSON.parse(raw);
  } catch {
    const match = raw.match(/({[\s\S]*})/);
    if (!match) return null;
    try {
      return JSON.parse(match[1]);
    } catch {
      return null;
    }
  }
};

const isOpenRouterRateLimitError = (error) => {
  const message = String(error?.message || "");
  return message.includes("OpenRouter Error 429") || message.includes('"code":429');
};

const getOpenRouterRateLimitMessage = () =>
  "Layanan AI sedang padat (rate limit). Coba lagi beberapa saat lagi.";

const createAiError = (code, message, extras = {}) => {
  const err = new Error(message);
  err.code = code;
  for (const [key, value] of Object.entries(extras || {})) {
    err[key] = value;
  }
  return err;
};

const isProviderMalformedJsonError = (error) => String(error?.code || "") === "provider_malformed_json";
const isProviderTimeoutError = (error) =>
  String(error?.code || "") === "provider_timeout" || String(error?.name || "") === "AbortError";
const isRetriableAiError = (error) =>
  isOpenRouterRateLimitError(error) || isProviderMalformedJsonError(error) || isProviderTimeoutError(error);

const getAiErrorCode = (error) => {
  if (isProviderMalformedJsonError(error)) return "provider_malformed_json";
  if (isProviderTimeoutError(error)) return "provider_timeout";
  if (isOpenRouterRateLimitError(error)) return "rate_limited";
  return "unknown";
};

const getAiUserFacingMessage = (error) => {
  if (isProviderMalformedJsonError(error)) {
    return "Respons AI belum utuh. Coba lagi sebentar.";
  }
  if (isProviderTimeoutError(error)) {
    return "Proses AI timeout. Coba lagi sebentar.";
  }
  if (isOpenRouterRateLimitError(error)) {
    return getOpenRouterRateLimitMessage();
  }
  return String(error?.message || "Layanan AI sedang bermasalah. Coba lagi.");
};

const normalizeHealthStatus = (value) => {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw) return null;
  if (["aman", "safe", "good", "healthy"].includes(raw)) return "aman";
  if (["perhatian", "warning", "caution", "watch"].includes(raw)) return "perhatian";
  if (["bahaya", "danger", "critical", "risk"].includes(raw)) return "bahaya";
  return null;
};

const clampHealthScore = (value) => {
  const score = Number(value);
  if (!Number.isFinite(score)) return null;
  return Math.max(0, Math.min(100, Math.round(score)));
};

const parseReportAiResult = (rawText) => {
  const parsed = parseJsonObject(rawText);
  const source = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  const fallbackArray = Array.isArray(parsed) ? parsed : [];

  const healthScore =
    clampHealthScore(source.healthScore) ??
    clampHealthScore(source.health_score) ??
    clampHealthScore(source.score);
  const healthStatus =
    normalizeHealthStatus(source.healthStatus) ??
    normalizeHealthStatus(source.health_status) ??
    (healthScore === null ? null : healthScore >= 75 ? "aman" : healthScore >= 50 ? "perhatian" : "bahaya");

  let recommendations = [];
  if (Array.isArray(source.recommendations)) {
    recommendations = source.recommendations;
  } else if (Array.isArray(source.suggestions)) {
    recommendations = source.suggestions;
  } else if (fallbackArray.length) {
    recommendations = fallbackArray;
  } else {
    recommendations = String(rawText || "")
      .split(/\r?\n/)
      .map((line) => line.replace(/^\s*(?:[-*•]|\d+[.)])\s*/, "").trim())
      .filter(Boolean);
  }

  const cleanRecommendations = recommendations
    .map((item) => String(item || "").trim())
    .filter(Boolean)
    .slice(0, 3);

  return {
    recommendations: cleanRecommendations,
    healthScore,
    healthStatus,
  };
};

const buildReportRecommendationPrompt = (targetLanguage, currentData) => {
  const summary = JSON.stringify(
    {
      monthlySummary: currentData?.monthlySummary || {},
      income: currentData?.income || {},
      expenses: currentData?.expenses || {},
      savings: currentData?.savings || {},
      debts: currentData?.debts || {},
      assets: currentData?.assets || {},
      budgets: currentData?.budgets || {},
      recentTransactions: Array.isArray(currentData?.transactions)
        ? currentData.transactions.slice(-20).map((tx) => ({
            date: tx?.date,
            amount: tx?.amount,
            type: tx?.type,
            category: tx?.category,
            account: tx?.account,
          }))
        : [],
    },
    null,
    2
  );

  return `Anda adalah analis keuangan pribadi untuk aplikasi Dompetku.
Tugas:
1) Berikan 3 rekomendasi paling berdampak dan praktis berdasarkan data user.
2) Prediksi health score 0-100 dan status: aman | perhatian | bahaya.
Bahasa output wajib: ${targetLanguage || "Indonesian"}.

Format output wajib JSON valid tanpa markdown:
{
  "healthScore": 0,
  "healthStatus": "aman",
  "recommendations": ["...", "...", "..."]
}

Rules:
- recommendations maksimal 3 item.
- tiap item singkat, jelas, bisa langsung dilakukan.
- jangan menambah teks di luar JSON.

Data user:
${summary}`;
};

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

const buildOpenRouterMessages = (systemInstruction, history, currentPrompt, replyTo) => {
  const openRouterMsgs = [{ role: "system", content: systemInstruction }];

  const historyLimit = 8;
  const filteredHistory = Array.isArray(history)
    ? history
        .filter((h) => h && typeof h.text === "string" && h.text.trim())
        .slice(-historyLimit)
    : [];

  for (const h of filteredHistory) {
    const role = h.role === "assistant" ? "assistant" : "user";
    let text = h.text;
    if (h.replyToText) {
      text = `[Membalas pesan: "${h.replyToText}"]\n${text}`;
    }
    openRouterMsgs.push({ role, content: text });
  }

  let finalPrompt = String(currentPrompt || "");
  if (replyTo && typeof replyTo.text === "string" && replyTo.text.trim()) {
    finalPrompt = `[Membalas pesan: "${replyTo.text}"]\n${finalPrompt}`;
  }
  openRouterMsgs.push({ role: "user", content: finalPrompt });

  return openRouterMsgs;
};

const openRouterFetch = async ({ model, timeoutMs, messages, maxTokens, stream, referer }) => {
  assertOpenRouterKey();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response;
    try {
      response = await fetch(OPENROUTER_URL, {
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
    } catch (error) {
      if (String(error?.name || "") === "AbortError") {
        throw createAiError("provider_timeout", `OpenRouter timeout after ${timeoutMs}ms`, {
          model,
          timeout_ms: timeoutMs,
        });
      }
      throw error;
    }

    if (!response.ok) {
      const err = await response.text();
      throw new Error(`OpenRouter Error ${response.status}: ${err}`);
    }

    return response;
  } finally {
    clearTimeout(timeout);
  }
};

const parseProviderJsonOrThrow = ({ rawText, context, model }) => {
  try {
    return JSON.parse(String(rawText || ""));
  } catch (error) {
    throw createAiError("provider_malformed_json", `Malformed JSON from provider in ${context}`, {
      model,
      raw_sample: String(rawText || "").slice(0, 300),
      parse_error: String(error?.message || error),
    });
  }
};

const callOpenRouterText = async (params) => {
  const startedAt = Date.now();
  const response = await openRouterFetch({ ...params, stream: false });
  const raw = await response.text();
  const data = parseProviderJsonOrThrow({
    rawText: raw,
    context: "callOpenRouterText",
    model: params.model,
  });
  const text = data?.choices?.[0]?.message?.content || "";
  return { text, ttftMs: Date.now() - startedAt, totalMs: Date.now() - startedAt };
};

const TRANSACTION_ACTION_NAMES = new Set(["addTransaction", "createTransaction"]);
const TRANSACTION_TYPE_VALUES = new Set(["income", "expense", "saving", "debt_payment", "asset"]);
const CLASSIFICATION_CONFIDENCE_THRESHOLD = 0.78;

const validateTransactionClassifications = async ({ prompt, actions, model, timeoutMs, referer }) => {
  const transactionActions = (Array.isArray(actions) ? actions : [])
    .map((action, index) => ({ action, index }))
    .filter(({ action }) => TRANSACTION_ACTION_NAMES.has(String(action?.name || "")));
  if (!transactionActions.length) return actions;

  try {
    const classifierSystem = `You are a semantic transaction classifier for a personal finance app.
Classify by money purpose, not by exact keywords or language.
Types:
- income: user receives money.
- expense: money is consumed as a cost, fee, loss, bill, food, transport, shopping, etc.
- saving: money moves into an app-style savings goal/target.
- debt_payment: money pays a liability, loan, installment, credit card, paylater, or debt.
- asset: user converts cash into wealth/investment/property/valuable item.
Consider Indonesian, English, slang, typos, and regional language by meaning. Do not classify by object name alone.
Return JSON only: {"classifications":[{"index":0,"type":"asset","category":"Bitcoin","confidence":0.92,"reason":"cash converted into investment asset"}]}.`;
    const classifierUser = JSON.stringify({
      prompt,
      actions: transactionActions.map(({ action, index }) => ({
        index,
        name: action.name,
        args: action.args || {},
      })),
    });
    const { text } = await callOpenRouterText({
      model,
      timeoutMs: Math.min(Math.max(4000, Number(timeoutMs) || 8000), 8000),
      messages: [
        { role: "system", content: classifierSystem },
        { role: "user", content: classifierUser },
      ],
      maxTokens: 600,
      referer,
    });
    const parsed = parseJsonObject(text);
    const rows = Array.isArray(parsed?.classifications) ? parsed.classifications : Array.isArray(parsed) ? parsed : [];
    if (!rows.length) return applyMinimalAssetKeywordFallback(actions, prompt);

    const byIndex = new Map();
    for (const row of rows) {
      const index = Number(row?.index);
      const type = String(row?.type || "").trim().toLowerCase();
      const confidence = Number(row?.confidence);
      if (!Number.isInteger(index) || !TRANSACTION_TYPE_VALUES.has(type) || !Number.isFinite(confidence)) continue;
      byIndex.set(index, {
        type,
        category: String(row?.category || "").trim(),
        reason: String(row?.reason || "").trim(),
        confidence: Math.max(0, Math.min(1, confidence)),
      });
    }

    return actions.map((action, index) => {
      const classification = byIndex.get(index);
      if (!classification || classification.confidence < CLASSIFICATION_CONFIDENCE_THRESHOLD) return action;
      if (!TRANSACTION_ACTION_NAMES.has(String(action?.name || ""))) return action;
      const args = { ...(action.args || {}) };
      args.type = classification.type;
      if (classification.category) {
        args.category = classification.category;
        delete args.kategori;
      }
      if (classification.reason) args.classification_reason = classification.reason.slice(0, 160);
      args.confidence = classification.confidence;
      if (classification.type !== "expense") {
        delete args.method;
        delete args.metode;
      }
      if (classification.type !== "income") {
        delete args.source;
        delete args.sumber;
      }
      return { ...action, args };
    });
  } catch (error) {
    console.warn("[classifier] transaction semantic check failed:", error?.message || error);
    return applyMinimalAssetKeywordFallback(actions, prompt);
  }
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
    const raw = await response.text();
    const data = parseProviderJsonOrThrow({
      rawText: raw,
      context: "callOpenRouterActions",
      model: params.model,
    });
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
    interval_value: 1,
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
      return true;
    }
    if (rule.frequency === "weekly") {
      const weekdays = rule.weekdays.length ? rule.weekdays : [1];
      if (!weekdays.includes(weekday)) return false;
      const weekIndex = Math.floor((serial - weeklyAnchorMonday) / 7);
      return weekIndex >= 0;
    }
    const monthDays = rule.month_days.length ? rule.month_days : [startD];
    if (!monthDays.includes(d)) return false;
    const mdiff = monthsDiff(y, m, startY, startM);
    return mdiff >= 0;
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

const normalizeName = (value) => {
  if (!value) return "";
  const text = String(value)
    .replace(/[^\p{L}\p{N}\s&\-_]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
  return text
    .split(" ")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
};

const parseAmount = (value) => {
  if (typeof value === "number" && Number.isFinite(value)) return Math.max(0, Math.round(value));
  if (typeof value !== "string") return 0;
  const lowered = value.toLowerCase();
  const isUsd = lowered.includes("$") || lowered.includes("usd");
  const text = lowered
    .replace(/rp/gi, "")
    .replace(/juta/gi, "000000")
    .replace(/jt/gi, "000000")
    .replace(/ribu/gi, "000")
    .replace(/rb/gi, "000")
    .replace(/k/gi, "000")
    .replace(/[^\d.-]/g, "");
  const parsed = Number(text);
  if (!Number.isFinite(parsed)) return 0;
  const normalizedValue = Math.max(0, parsed);
  if (isUsd) return Math.round(normalizedValue * 17000);
  return Math.round(normalizedValue);
};

const findBestKey = (query, keys) => {
  const normalize = (v) => String(v || "").toLowerCase().replace(/[^a-z0-9\s]/g, " ").replace(/\s+/g, " ").trim();
  const normalizedQuery = normalize(query);
  if (!normalizedQuery) return null;
  const exact = keys.find((name) => normalize(name) === normalizedQuery);
  if (exact) return exact;
  return keys.find((name) => normalize(name).includes(normalizedQuery) || normalizedQuery.includes(normalize(name))) || null;
};

const ensureTxDate = (value) => {
  const localYmdHms = () => {
    const now = new Date();
    const y = now.getFullYear();
    const m = String(now.getMonth() + 1).padStart(2, "0");
    const d = String(now.getDate()).padStart(2, "0");
    const hh = String(now.getHours()).padStart(2, "0");
    const mm = String(now.getMinutes()).padStart(2, "0");
    return `${y}-${m}-${d}T${hh}:${mm}`;
  };
  const raw = String(value || "").trim();
  if (!raw) return localYmdHms();
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) return `${raw}T00:00`;
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(raw)) return raw.slice(0, 16);
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) return localYmdHms();
  const y = parsed.getFullYear();
  const m = String(parsed.getMonth() + 1).padStart(2, "0");
  const d = String(parsed.getDate()).padStart(2, "0");
  const hh = String(parsed.getHours()).padStart(2, "0");
  const mm = String(parsed.getMinutes()).padStart(2, "0");
  return `${y}-${m}-${d}T${hh}:${mm}`;
};

const resolveWalletName = (data, candidate) => {
  const given = normalizeName(candidate);
  const keys = Object.keys(data.wallets || {});
  if (!given) return keys[0] || "Total Keuangan";
  return findBestKey(given, keys) || given;
};

const ensureWalletExists = (data, walletName, walletType = "Lainnya", startingBalance = 0) => {
  if (data.wallets?.[walletName]) return;
  data.wallets = {
    ...(data.wallets || {}),
    [walletName]: {
      type: walletType,
      startingBalance: Math.max(0, Math.round(startingBalance)),
      currentBalance: Math.max(0, Math.round(startingBalance)),
    },
  };
};

const adjustPlanByDelta = (data, planNameRaw, delta) => {
  const planName = normalizeName(planNameRaw || "Tabungan");
  if (!planName || !Number.isFinite(delta) || delta === 0) return;
  const existingName = findBestKey(planName, Object.keys(data.tabunganPlans || {})) || planName;
  const existing = data.tabunganPlans?.[existingName];
  const current = Math.max(0, Number(existing?.current || 0) + Math.round(delta));
  const target = Math.max(current, Number(existing?.target || 0));
  const now = new Date().toISOString();
  data.tabunganPlans = {
    ...(data.tabunganPlans || {}),
    [existingName]: {
      target,
      current,
      note: existing?.note || "",
      createdAt: existing?.createdAt || now,
      updatedAt: now,
    },
  };
};

const applyMoneyDelta = (data, tx, direction) => {
  const amount = (Number(tx.amount) || 0) * direction;
  const category = tx.category || "Lainnya";
  if (!amount) return;
  const upsert = (section, key) => {
    const map = { ...(data[section] || {}) };
    map[key] = Number(map[key] || 0) + amount;
    data[section] = map;
  };
  if (tx.type === "income") upsert("income", category);
  if (tx.type === "expense") upsert("expenses", category);
  if (tx.type === "saving") upsert("savings", category);
  if (tx.type === "asset") upsert("assets", category);
  if (tx.type === "debt_payment") {
    upsert("expenses", "Cicilan");
    if (typeof data.debts?.[category] === "number") {
      data.debts = {
        ...(data.debts || {}),
        [category]: Math.max(0, Number(data.debts?.[category] || 0) - amount),
      };
    }
  }
};

const syncAccounts = (data) => ({
  ...data,
  accounts: {
    ...(data.accounts || { assets: {}, liabilities: {}, equity: {}, revenue: {}, expenses: {} }),
    assets: data.assets,
    liabilities: data.debts,
    equity: data.savings,
    revenue: data.income,
    expenses: data.expenses,
  },
});

const syncWalletsWithTransactions = (data) => {
  const next = { ...data };
  const wallets = {};
  for (const name of Object.keys(next.wallets || {})) {
    wallets[name] = { ...next.wallets[name], currentBalance: next.wallets[name].startingBalance || 0 };
  }
  const txs = Array.isArray(next.transactions) ? next.transactions : [];
  for (const tx of txs) {
    const walletName = tx.account || "Total Keuangan";
    if (!wallets[walletName]) {
      wallets[walletName] = { type: "Lainnya", startingBalance: 0, currentBalance: 0 };
    }
    const amount = Number(tx.amount) || 0;
    if (tx.type === "income") {
      wallets[walletName].currentBalance += amount;
    } else {
      wallets[walletName].currentBalance -= amount;
    }
  }
  next.wallets = wallets;
  return next;
};

const syncBudgetsWithTransactions = (data) => {
  const next = { ...data };
  const budgets = {};
  for (const name of Object.keys(next.budgets || {})) {
    budgets[name] = { ...next.budgets[name], spent: 0 };
  }
  const txs = Array.isArray(next.transactions) ? next.transactions : [];
  for (const tx of txs) {
    if (tx.type !== "expense") continue;
    const catName = tx.category || "Lainnya";
    const budgetName = findBestKey(catName, Object.keys(budgets));
    if (budgetName) {
      budgets[budgetName].spent = Number(budgets[budgetName].spent || 0) + Number(tx.amount || 0);
    }
  }
  next.budgets = budgets;
  return next;
};

const normalizeAccountingDataServerSide = (data) => {
  const cleanObj = (obj) => {
    const next = {};
    if (!obj || typeof obj !== "object") return next;
    for (const key of Object.keys(obj)) {
      if (typeof obj[key] === "number") next[key] = obj[key];
    }
    return next;
  };
  const d = data || {};
  return {
    wallets: isObject(d.wallets) ? d.wallets : {},
    tabunganPlans: isObject(d.tabunganPlans) ? d.tabunganPlans : {},
    budgets: isObject(d.budgets) ? d.budgets : {},
    transactions: Array.isArray(d.transactions) ? d.transactions : [],
    income: cleanObj(d.income),
    expenses: cleanObj(d.expenses),
    savings: cleanObj(d.savings),
    debts: cleanObj(d.debts),
    assets: cleanObj(d.assets),
    categories: isObject(d.categories) ? d.categories : { income: [], expenses: [], assets: [], debts: [], saving: [], debt_payment: [] },
  };
};

const upsertTabunganPlan = (data, nameRaw, targetRaw, currentOverride, noteRaw) => {
  const name = normalizeName(nameRaw);
  if (!name) return false;
  const existingName = findBestKey(name, Object.keys(data.tabunganPlans || {})) || name;
  const existing = data.tabunganPlans?.[existingName];
  const target = (targetRaw !== undefined && targetRaw !== null) ? parseAmount(targetRaw) : Number(existing?.target || 0);
  const nextCurrent = typeof currentOverride === "number" ? Math.max(0, Math.round(currentOverride)) : Number(existing?.current || 0);
  const now = new Date().toISOString();
  data.tabunganPlans = {
    ...(data.tabunganPlans || {}),
    [existingName]: {
      target,
      current: nextCurrent,
      note: String(noteRaw || existing?.note || "").trim(),
      createdAt: existing?.createdAt || now,
      updatedAt: now,
    },
  };
  return true;
};

const makeTxFromArgs = (data, args, existing) => {
  const txType = args.type || existing?.type;
  if (!txType) return null;
  const amountRaw = (args.amount !== undefined || args.jumlah !== undefined) ? parseAmount(args.amount) || parseAmount(args.jumlah) : Number(existing?.amount || 0);
  const amount = amountRaw > 0 ? amountRaw : 17000;
  const walletName = resolveWalletName(data, args.account || existing?.account);
  ensureWalletExists(data, walletName);
  const baseCategory = normalizeName(args.category || args.kategori || existing?.category || "");
  const category = baseCategory || (txType === "income" ? "Lainnya" : txType === "expense" ? "Lainnya" : txType === "saving" ? "Tabungan" : txType === "asset" ? "Investasi" : "Cicilan");
  const tx = {
    id: String(existing?.id || args.id || `tx_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`),
    date: ensureTxDate(args.date || args.tanggal || existing?.date),
    description: String(args.description || args.catatan || existing?.description || `${txType} ${category}`).trim(),
    amount,
    type: txType,
    category,
    account: walletName,
    note: String(args.note || args.catatan || existing?.note || "").trim() || undefined,
    source: txType === "income" ? String(args.source || args.sumber || existing?.source || "").trim() || undefined : undefined,
    method: txType === "expense" ? String(args.method || args.metode || existing?.method || "QRIS").trim() || "QRIS" : undefined,
  };
  return tx;
};

const executeAgentActionsServerSide = (currentData, actions) => {
  let next = normalizeAccountingDataServerSide(currentData);
  const notices = [];
  const actionSummaries = [];

  for (const action of actions) {
    const name = action?.name;
    const args = action?.args || {};
    if (!name) continue;

    if (name === "createWallet" || name === "AddAkunDompet") {
      const walletName = normalizeName(args.name);
      const walletType = normalizeName(args.type) || "Lainnya";
      const saldoAwal = parseAmount(args.saldo_awal !== undefined ? args.saldo_awal : args.startingBalance);
      if (!walletName) continue;
      ensureWalletExists(next, walletName, walletType, saldoAwal);
      actionSummaries.push(`Dompet ${walletName} dibuat.`);
      continue;
    }

    if (name === "createTabungan" || name === "createTabunganPlan") {
      const ok = upsertTabunganPlan(next, args.name, args.target, undefined, args.note);
      if (ok) actionSummaries.push(`Tabungan ${normalizeName(args.name)} dibuat.`);
      continue;
    }

    if (name === "createGoal" || name === "updateTabunganPlan") {
      const current = args.current !== undefined ? parseAmount(args.current) : undefined;
      const existing = normalizeName(args.name);
      if (!existing) continue;
      const targetRaw = args.target !== undefined ? args.target : next.tabunganPlans?.[existing]?.target;
      const ok = upsertTabunganPlan(next, args.name, targetRaw, current, args.note);
      if (ok) actionSummaries.push(`Tabungan ${existing} diperbarui.`);
      continue;
    }

    if (name === "addTabungan") {
      const planName = normalizeName(args.name);
      const amount = parseAmount(args.amount) || parseAmount(args.jumlah) || 17000;
      if (!planName || amount <= 0) continue;
      const walletName = resolveWalletName(next, args.account);
      ensureWalletExists(next, walletName);
      adjustPlanByDelta(next, planName, amount);
      const tx = makeTxFromArgs(next, {
        ...args,
        type: "saving",
        category: planName,
        description: String(args.note || "").trim() || `Tambah tabungan ${planName}`,
      });
      if (!tx) continue;
      next.transactions = [...(next.transactions || []), tx];
      applyMoneyDelta(next, tx, 1);
      actionSummaries.push(`Saldo tabungan ${planName} ditambah.`);
      continue;
    }

    if (name === "createBudget" || name === "updateBudget") {
      const budgetName = normalizeName(args.name);
      const limit = parseAmount(args.limit);
      if (!budgetName || limit <= 0) continue;
      const existingName = findBestKey(budgetName, Object.keys(next.budgets || {})) || budgetName;
      next.budgets = {
        ...(next.budgets || {}),
        [existingName]: {
          limit,
          spent: Number(next.budgets?.[existingName]?.spent || 0),
          note: String(args.note || next.budgets?.[existingName]?.note || "").trim(),
          updatedAt: new Date().toISOString(),
        },
      };
      actionSummaries.push(`Budget ${existingName} diperbarui.`);
      continue;
    }

    if (name === "addTransaction" || name === "createTransaction") {
      const tx = makeTxFromArgs(next, args);
      if (!tx) continue;
      if (tx.type === "saving") adjustPlanByDelta(next, tx.category, tx.amount);
      next.transactions = [...(next.transactions || []), tx];
      applyMoneyDelta(next, tx, 1);
      actionSummaries.push(`Transaksi ${tx.id} ditambahkan.`);
      continue;
    }
  }

  next = syncAccounts(next);
  next = syncWalletsWithTransactions(next);
  next = syncBudgetsWithTransactions(next);

  return { updatedData: normalizeAccountingDataServerSide(next), notices, actionSummaries };
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
    const text = await response.text().catch(() => "");
    throw new Error(`Supabase REST ${response.status}: ${text}`);
  }
  if (response.status === 204) return null;
  const text = await response.text().catch(() => "");
  if (!text || !text.trim()) return null;
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`Failed to parse Supabase JSON response: ${err.message}. Raw content: ${text}`);
  }
};

const firstRow = (value) => (Array.isArray(value) ? value[0] : value);
const toSafeTrimmed = (value) => String(value || "").trim();

const resolveFirebaseProjectId = () => {
  const fromEnv = toSafeTrimmed(process.env.FIREBASE_PROJECT_ID);
  if (fromEnv) return fromEnv;
  const fromAccount = toSafeTrimmed(resolveFirebaseServiceAccount().projectId);
  return fromAccount;
};

const sendFcmDataMessage = async ({ token, data, accessToken: providedAccessToken }) => {
  const projectId = resolveFirebaseProjectId();
  if (!projectId) throw new Error("FIREBASE_PROJECT_ID is missing.");
  if (!token) throw new Error("FCM token is required.");

  const accessToken = providedAccessToken || await getFirebaseMessagingAccessToken();
  const response = await fetch(`https://fcm.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/messages:send`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json; charset=UTF-8",
    },
    body: JSON.stringify({
      message: {
        token,
        data,
        android: { priority: "high" },
      },
    }),
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => "");
    throw new Error(`FCM send failed (${response.status}): ${errorText}`);
  }
  return response.json();
};

const assertInternalApiKey = (req) => {
  const internalKey = toSafeTrimmed(process.env.INTERNAL_API_KEY);
  const internalKeyHeader = toSafeTrimmed(req.headers["x-internal-key"]);
  return Boolean(internalKey && internalKeyHeader && internalKeyHeader === internalKey);
};

const readAllAndroidDeviceTokens = async () => {
  const pageSize = 1000;
  const rows = [];
  for (let offset = 0; offset < 50; offset += pageSize) {
    const page = await supabaseRestFetch(
      `${DEVICE_TOKEN_TABLE}?platform=eq.android&select=user_id,fcm_token,updated_at&order=updated_at.desc&limit=${pageSize}&offset=${offset}`
    );
    const items = Array.isArray(page) ? page : [];
    rows.push(...items);
    if (items.length < pageSize) break;
  }

  const byToken = new Map();
  for (const row of rows) {
    const token = toSafeTrimmed(row?.fcm_token);
    if (!token || byToken.has(token)) continue;
    byToken.set(token, {
      userId: toSafeTrimmed(row?.user_id),
      token,
    });
  }
  return Array.from(byToken.values());
};

const resolveFamilyContext = async (userId) => {
  try {
    // 1. Check if user is a member of a family
    const memberRows = await supabaseRestFetch(
      `family_members?user_id=eq.${encodeURIComponent(userId)}&select=family_id,role,can_create,can_edit,can_delete&limit=1`
    ).catch(() => null);
    const member = firstRow(memberRows);

    if (member) {
      const familyRows = await supabaseRestFetch(
        `families?id=eq.${encodeURIComponent(member.family_id)}&select=owner_id,invite_code&limit=1`
      ).catch(() => null);
      const family = firstRow(familyRows);
      if (family) {
        return {
          inFamily: true,
          isOwner: false,
          ownerId: family.owner_id,
          inviteCode: family.invite_code,
          role: "member",
          permissions: {
            can_create: !!member.can_create,
            can_edit: !!member.can_edit,
            can_delete: !!member.can_delete,
          },
          familyId: member.family_id,
        };
      }
    }

    // 2. Check if user is owner of a family
    const ownerRows = await supabaseRestFetch(
      `families?owner_id=eq.${encodeURIComponent(userId)}&select=id,invite_code&limit=1`
    ).catch(() => null);
    const ownerFamily = firstRow(ownerRows);

    if (ownerFamily) {
      const membersRows = await supabaseRestFetch(
        `family_members?family_id=eq.${encodeURIComponent(ownerFamily.id)}&select=id,user_id,role,can_create,can_edit,can_delete,created_at`
      ).catch(() => []);
      const members = Array.isArray(membersRows) ? membersRows : [];
      const membersWithProfiles = await Promise.all(
        members.map(async (m) => {
          const profileRows = await supabaseRestFetch(
            `profiles?id=eq.${encodeURIComponent(m.user_id)}&select=display_name`
          ).catch(() => null);
          const profile = firstRow(profileRows);
          return {
            ...m,
            display_name: profile?.display_name || "Anggota Keluarga",
          };
        })
      );

      return {
        inFamily: true,
        isOwner: true,
        ownerId: userId,
        inviteCode: ownerFamily.invite_code,
        role: "owner",
        permissions: {
          can_create: true,
          can_edit: true,
          can_delete: true,
        },
        familyId: ownerFamily.id,
        members: membersWithProfiles,
      };
    }

    return {
      inFamily: false,
      isOwner: false,
      ownerId: userId,
      role: null,
      permissions: null,
      familyId: null,
    };
  } catch (err) {
    console.error("[resolveFamilyContext] error:", err);
    return {
      inFamily: false,
      isOwner: false,
      ownerId: userId,
      role: null,
      permissions: null,
      familyId: null,
    };
  }
};

const canUserCreateFamily = async (userId) => {
  try {
    const [overrideRows, subRows] = await Promise.all([
      supabaseRestFetch(`${ACCESS_OVERRIDE_TABLE}?user_id=eq.${encodeURIComponent(userId)}&select=role&limit=1`).catch(() => null),
      supabaseRestFetch(`${SUBSCRIPTION_TABLE}?user_id=eq.${encodeURIComponent(userId)}&status=eq.active&select=plan,status&order=created_at.desc&limit=1`).catch(() => null),
    ]);
    const override = firstRow(overrideRows);
    if (override?.role === "admin") return true;

    const sub = firstRow(subRows);
    if (sub?.status === "active" && (sub.plan === "family" || sub.plan === "family_pro" || sub.plan === "premium")) {
      return true;
    }
    return false;
  } catch (err) {
    console.error("[canUserCreateFamily] failed:", err);
    return false;
  }
};

const validateSnapshotPermissions = (oldSnapshot, newSnapshot, permissions) => {
  const oldTxs = oldSnapshot?.transactions || [];
  const newTxs = newSnapshot?.transactions || [];

  const oldMap = new Map(oldTxs.map(t => [t.id, t]));
  const newMap = new Map(newTxs.map(t => [t.id, t]));

  let hasCreate = false;
  let hasEdit = false;
  let hasDelete = false;

  for (const newTx of newTxs) {
    const oldTx = oldMap.get(newTx.id);
    if (!oldTx) {
      hasCreate = true;
    } else {
      if (
        newTx.amount !== oldTx.amount ||
        newTx.category !== oldTx.category ||
        newTx.description !== oldTx.description ||
        newTx.date !== oldTx.date ||
        newTx.type !== oldTx.type ||
        newTx.account !== oldTx.account ||
        newTx.note !== oldTx.note ||
        newTx.method !== oldTx.method
      ) {
        hasEdit = true;
      }
    }
  }

  for (const oldTx of oldTxs) {
    if (!newMap.has(oldTx.id)) {
      hasDelete = true;
    }
  }

  let hasNonTxEdits = false;
  if (!permissions.can_edit) {
    const fieldsToCheck = ['budgets', 'goals', 'tabunganPlans', 'wallets', 'categories', 'metadata'];
    for (const f of fieldsToCheck) {
      if (JSON.stringify(oldSnapshot[f]) !== JSON.stringify(newSnapshot[f])) {
        hasNonTxEdits = true;
        break;
      }
    }
  }

  if (hasCreate && !permissions.can_create) {
    return { ok: false, error: "Anda tidak memiliki izin untuk menambah transaksi." };
  }
  if (hasEdit && !permissions.can_edit) {
    return { ok: false, error: "Anda tidak memiliki izin untuk mengubah transaksi." };
  }
  if (hasDelete && !permissions.can_delete) {
    return { ok: false, error: "Anda tidak memiliki izin untuk menghapus transaksi." };
  }
  if (hasNonTxEdits && !permissions.can_edit) {
    return { ok: false, error: "Anda tidak memiliki izin untuk mengubah anggaran, tabungan, dompet, atau kategori keluarga." };
  }

  return { ok: true };
};

const resolveUserAccessPlanFromDB = async (userId) => {
  try {
    const memberRows = await supabaseRestFetch(
      `family_members?user_id=eq.${encodeURIComponent(userId)}&select=family_id&limit=1`
    ).catch(() => null);
    const member = firstRow(memberRows);
    let targetUserId = userId;
    if (member) {
      const familyRows = await supabaseRestFetch(
        `families?id=eq.${encodeURIComponent(member.family_id)}&select=owner_id&limit=1`
      ).catch(() => null);
      const family = firstRow(familyRows);
      if (family) {
        targetUserId = family.owner_id;
      }
    }

    const [overrideRows, subRows] = await Promise.all([
      supabaseRestFetch(`${ACCESS_OVERRIDE_TABLE}?user_id=eq.${encodeURIComponent(targetUserId)}&select=role&limit=1`).catch(() => null),
      supabaseRestFetch(`${SUBSCRIPTION_TABLE}?user_id=eq.${encodeURIComponent(targetUserId)}&status=eq.active&select=plan,status&order=created_at.desc&limit=1`).catch(() => null),
    ]);
    const override = firstRow(overrideRows);
    if (override?.role === "admin") return "admin";
    const sub = firstRow(subRows);
    if (sub?.status === "active") return "premium";
    return "free";
  } catch (err) {
    console.warn("[resolveUserAccessPlanFromDB] failed:", err?.message);
    return null; // null = fallback to client-provided value
  }
};

const normalizePlanCode = (value) =>
  String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_");

const isAutoTransactionPlanEligible = (plan) => AUTO_TRANSACTION_PLAN_CODES.has(normalizePlanCode(plan));

const resolveAutoTransactionAccess = async (targetUserId) => {
  try {
    const [overrideRows, subRows] = await Promise.all([
      supabaseRestFetch(`${ACCESS_OVERRIDE_TABLE}?user_id=eq.${encodeURIComponent(targetUserId)}&select=role&limit=1`).catch(() => null),
      supabaseRestFetch(
        `${SUBSCRIPTION_TABLE}?user_id=eq.${encodeURIComponent(
          targetUserId
        )}&status=eq.active&select=plan,status&order=created_at.desc&limit=1`
      ).catch(() => null),
    ]);
    const override = firstRow(overrideRows);
    if (override?.role === "admin") return { ok: true, plan: "admin" };

    const sub = firstRow(subRows);
    const plan = normalizePlanCode(sub?.plan);
    return {
      ok: sub?.status === "active" && isAutoTransactionPlanEligible(plan),
      plan,
    };
  } catch (error) {
    console.warn("[resolveAutoTransactionAccess] failed:", error?.message);
    return { ok: false, plan: "" };
  }
};


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
  return [];
};

const upsertMasterCategories = async (userId, items = []) => {
  return [];
};

const buildSnapshotCategoriesFromMaster = (rows, previous) => {
  const prev = normalizeAccountingData(previous || {}).categories;
  return {
    income: sortUnique(prev.income),
    expenses: sortUnique(prev.expenses),
    assets: sortUnique(prev.assets),
    debts: sortUnique(prev.debts),
    debt_payment: sortUnique(prev.debt_payment),
    saving: sortUnique(prev.saving),
  };
};

const ensureCategoryMasterAndMirrorSnapshot = async (userId, rawAccountingData) => {
  const normalized = normalizeAccountingData(rawAccountingData || {});
  return { mirrored: normalized, rows: [] };
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

  const familyContext = await resolveFamilyContext(userId);
  const targetUserIdForSub = familyContext.inFamily ? familyContext.ownerId : userId;

  const [profile, subscription, accessOverride] = await Promise.all([
    readOrNull("profile", `profiles?id=eq.${encodeURIComponent(userId)}&select=display_name,referral_code`),
    readOrNull(
      "subscription",
      `subscriptions?user_id=eq.${encodeURIComponent(
        targetUserIdForSub
      )}&status=eq.active&select=plan,status,created_at&order=created_at.desc&limit=1`
    ),
    readOrNull(
      "access override",
      `${ACCESS_OVERRIDE_TABLE}?user_id=eq.${encodeURIComponent(
        targetUserIdForSub
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
    familyContext,
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

    try {
      const tokenRows = await supabaseRestFetch(
        `${DEVICE_TOKEN_TABLE}?user_id=eq.${encodeURIComponent(rule.user_id)}&platform=eq.android&select=fcm_token,updated_at&order=updated_at.desc&limit=1`
      ).catch(() => null);
      const fcmToken = toSafeTrimmed(firstRow(tokenRows)?.fcm_token);
      if (fcmToken) {
        const rupiah = (val) => "Rp" + Math.round(val || 0).toLocaleString("id-ID");
        const detail = [
          rule.description || rule.category || 'Transaksi otomatis',
          Number(rule.amount || 0) > 0 ? rupiah(Number(rule.amount || 0)) : '',
        ].filter(Boolean).join(' - ');

        await sendFcmDataMessage({
          token: fcmToken,
          data: {
            conversationId: "recurring_run",
            messageId: `recurring_${runMarker.id}_${Date.now()}`,
            senderName: "Dompetku",
            messageText: `Transaksi otomatis tercatat: ${detail}`,
            timestamp: String(Date.now()),
            avatarUrl: "",
          }
        }).catch((err) => console.error("[recurring-push] failed to send push:", err.message));
      }
    } catch (pushErr) {
      console.error("[recurring-push] FCM query/send failed:", pushErr.message);
    }

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
  const autoAccess = await resolveAutoTransactionAccess(currentRule.user_id);
  if (!autoAccess.ok) {
    const nextRun = computeNextRunUtc(currentRule, new Date(now.getTime() + 60_000));
    await updateRecurringRuleRow(currentRule.id, {
      next_run_at_utc: nextRun ? nextRun.toISOString() : null,
      is_active: Boolean(nextRun) && currentRule.is_active,
    });
    return;
  }
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
app.use(
  cors({
    origin(origin, callback) {
      if (isAllowedOrigin(origin)) return callback(null, true);
      return callback(new Error(`Origin not allowed: ${origin}`));
    },
  })
);
app.use(express.json({ limit: "10mb" }));
app.use((error, req, res, next) => {
  const errorType = String(error?.type || "");
  const isJsonSyntaxError =
    (error instanceof SyntaxError && Object.prototype.hasOwnProperty.call(error, "body")) ||
    errorType === "entity.parse.failed";
  const isPayloadTooLarge = errorType === "entity.too.large";
  if (!isJsonSyntaxError && !isPayloadTooLarge) return next(error);

  const requestPath = String(req?.path || "");
  const isConfirmPath = requestPath === "/api/agent/actions/confirm";
  const status = isPayloadTooLarge ? 413 : 400;
  const errorCode = isPayloadTooLarge ? "request_body_too_large" : "request_json_invalid";
  const errorDomain = isConfirmPath ? "confirm_error" : "request_parse_error";
  const userMessage = isPayloadTooLarge
    ? "Payload request terlalu besar. Coba kirim ulang data yang lebih ringkas."
    : "Format JSON request tidak valid. Silakan coba lagi.";

  console.warn(
    "[request-json-error]",
    JSON.stringify({
      route: requestPath,
      status: "failed",
      error_code: errorCode,
      error_domain: errorDomain,
      detail: String(error?.message || "").slice(0, 160),
    })
  );
  return res.status(status).json({
    ok: false,
    error: userMessage,
    error_code: errorCode,
    error_domain: errorDomain,
  });
});

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

app.get("/api/notification-messages", requireSupabaseUser, async (_req, res) => {
  try {
    const messages = await readNotificationMessages();
    return res.json(messages);
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to read notification messages." });
  }
});

app.post("/api/push/token", requireSupabaseUser, async (req, res) => {
  try {
    const userId = String(req.authUser.id);
    const fcmToken = toSafeTrimmed(req.body?.fcmToken);
    const platform = toSafeTrimmed(req.body?.platform || "android");
    const deviceId = toSafeTrimmed(req.body?.deviceId);

    if (!fcmToken) return res.status(400).json({ error: "fcmToken wajib diisi." });

    const rows = await supabaseRestFetch(`${DEVICE_TOKEN_TABLE}?on_conflict=user_id,device_id&select=*`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=representation" },
      body: JSON.stringify([
        {
          user_id: userId,
          fcm_token: fcmToken,
          platform: platform || "android",
          device_id: deviceId || `device-${Date.now()}`,
          updated_at: new Date().toISOString(),
        },
      ]),
    });

    return res.json({ ok: true, token: firstRow(rows) || null });
  } catch (error) {
    return res.status(500).json({
      error: error?.message || "Gagal menyimpan token push.",
      hint: "Pastikan tabel user_device_tokens sudah dibuat di Supabase.",
    });
  }
});

app.post("/api/push/chat", requireSupabaseUser, async (req, res) => {
  try {
    const authUserId = String(req.authUser.id);
    const internalKeyHeader = toSafeTrimmed(req.headers["x-internal-key"]);
    const internalKey = toSafeTrimmed(process.env.INTERNAL_API_KEY);
    const isInternal = internalKey && internalKeyHeader && internalKeyHeader === internalKey;

    const requestedUserId = toSafeTrimmed(req.body?.userId);
    const targetUserId = requestedUserId || authUserId;
    if (!isInternal && targetUserId !== authUserId) {
      return res.status(403).json({ error: "Tidak boleh mengirim push ke user lain." });
    }

    const conversationId = toSafeTrimmed(req.body?.conversationId || "default");
    const messageId = toSafeTrimmed(req.body?.messageId || `msg_${Date.now()}`);
    const senderName = toSafeTrimmed(req.body?.senderName || "Agen Dompetku");
    const messageText = toSafeTrimmed(req.body?.messageText);
    const avatarUrl = toSafeTrimmed(req.body?.avatarUrl);
    const directFcmToken = toSafeTrimmed(req.body?.fcmToken);
    const timestamp = String(Number(req.body?.timestamp) || Date.now());

    if (!messageText) return res.status(400).json({ error: "messageText wajib diisi." });

    let fcmToken = directFcmToken;
    if (!fcmToken) {
      const rows = await supabaseRestFetch(
        `${DEVICE_TOKEN_TABLE}?user_id=eq.${encodeURIComponent(targetUserId)}&platform=eq.android&select=fcm_token,updated_at&order=updated_at.desc&limit=1`
      ).catch(() => null);
      fcmToken = toSafeTrimmed(firstRow(rows)?.fcm_token);
    }
    if (!fcmToken) {
      return res.status(404).json({
        error: "FCM token user belum terdaftar.",
        hint: "Panggil POST /api/push/token dari device user setelah login.",
      });
    }

    const fcmResponse = await sendFcmDataMessage({
      token: fcmToken,
      data: {
        conversationId,
        messageId,
        senderName,
        messageText,
        timestamp,
        avatarUrl: avatarUrl || "",
      },
    });

    return res.json({
      ok: true,
      targetUserId,
      conversationId,
      messageId,
      fcmResponse,
    });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Gagal kirim push chat." });
  }
});

app.post("/api/push/chat/reply", requireSupabaseUser, async (req, res) => {
  try {
    const userId = String(req.authUser.id);
    const { conversationId, messageId, replyText } = req.body || {};

    if (!replyText) {
      return res.status(400).json({ error: "replyText wajib diisi." });
    }

    // 1. Fetch user's current finance snapshot from Supabase
    const snapshotRows = await supabaseRestFetch(
      `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(userId)}&select=accounting_data,data_version`
    ).catch(() => null);
    const snapshot = firstRow(snapshotRows) || { accounting_data: {}, data_version: 0 };
    const currentData = snapshot.accounting_data || {};

    // 2. We use empty history for notification replies
    const history = [];

    // 3. Process the reply using OpenRouter action system
    const targetLanguage = "Indonesian";
    const accessPlan = await resolveUserAccessPlanFromDB(userId).catch(() => "free") || "free";
    const modelPolicy = resolveAiRouteModelPolicy({
      route: "agent_actions",
      prompt: replyText,
      accessPlan,
    });

    const compactData = buildCompactData(currentData);
    const actionSystem = buildActionSystemInstruction(targetLanguage, compactData);
    const messages = buildOpenRouterMessages(
      actionSystem,
      history,
      replyText
    );

    let usedModel = modelPolicy.primaryModel;
    let fallbackUsed = false;
    let result = { actions: [], assistantText: "" };
    let lastRouteError = null;

    for (let idx = 0; idx < modelPolicy.modelFallbackChain.length; idx += 1) {
      const candidateModel = modelPolicy.modelFallbackChain[idx];
      const candidateTimeout = idx === 0 ? modelPolicy.primaryTimeout : modelPolicy.secondaryTimeout;
      try {
        let candidateResult = await callOpenRouterActions({
          model: candidateModel,
          timeoutMs: candidateTimeout,
          messages,
          referer: req.headers.referer,
          toolChoice: "auto",
        });

        if (!candidateResult.actions.length) {
          candidateResult = await callOpenRouterActions({
            model: candidateModel,
            timeoutMs: candidateTimeout,
            messages,
            referer: req.headers.referer,
            toolChoice: "required",
          });
        }

        if (candidateResult.actions.length) {
          usedModel = candidateModel;
          fallbackUsed = idx > 0;
          result = candidateResult;
          break;
        }
      } catch (err) {
        lastRouteError = err;
      }
    }

    // 4. Execute any generated actions server-side
    let executeSummary = "";
    if (result.actions && result.actions.length > 0) {
      const filteredActions = result.actions.filter(isAllowedAgentAction);
      if (filteredActions.length > 0) {
        const execution = executeAgentActionsServerSide(currentData, filteredActions);
        const nextVersion = Date.now();
        await supabaseRestFetch(`${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(userId)}`, {
          method: "PATCH",
          body: JSON.stringify({
            accounting_data: execution.updatedData,
            data_version: nextVersion,
            updated_at: new Date().toISOString(),
          }),
        }).catch((err) => console.error("[push-reply] failed to update finance snapshot:", err.message));
        executeSummary = execution.actionSummaries.join(" ") + " " + execution.notices.join(" ");
      }
    }

    const responseText = result.assistantText || executeSummary || "Pesan diproses.";

    // 5. Send FCM message back to the user's device
    const tokenRows = await supabaseRestFetch(
      `${DEVICE_TOKEN_TABLE}?user_id=eq.${encodeURIComponent(userId)}&platform=eq.android&select=fcm_token,updated_at&order=updated_at.desc&limit=1`
    ).catch(() => null);
    const fcmToken = toSafeTrimmed(firstRow(tokenRows)?.fcm_token);

    if (fcmToken) {
      await sendFcmDataMessage({
        token: fcmToken,
        data: {
          conversationId: conversationId || "default",
          messageId: `msg_${Date.now()}`,
          senderName: "Agen Dompetku",
          messageText: responseText,
          timestamp: String(Date.now()),
          avatarUrl: "",
        },
      }).catch((err) => console.error("[push-reply] failed to send FCM:", err.message));
    }

    return res.json({ ok: true, responseText });
  } catch (error) {
    console.error("[push-reply] Endpoint error:", error);
    return res.status(500).json({ error: error?.message || "Gagal memproses reply chat." });
  }
});

app.post("/api/push/chat/broadcast", async (req, res) => {
  try {
    if (!assertInternalApiKey(req)) {
      return res.status(401).json({ error: "Internal API key tidak valid." });
    }

    const conversationId = toSafeTrimmed(req.body?.conversationId || "broadcast");
    const messageId = toSafeTrimmed(req.body?.messageId || `broadcast_${Date.now()}`);
    const senderName = toSafeTrimmed(req.body?.senderName || "Agen Dompetku");
    const messageText = toSafeTrimmed(req.body?.messageText);
    const avatarUrl = toSafeTrimmed(req.body?.avatarUrl);
    const timestamp = String(Number(req.body?.timestamp) || Date.now());

    if (!messageText) return res.status(400).json({ error: "messageText wajib diisi." });

    const targets = await readAllAndroidDeviceTokens();
    if (!targets.length) {
      return res.json({ ok: true, sent: 0, failed: 0, totalTargets: 0, failures: [] });
    }

    const accessToken = await getFirebaseMessagingAccessToken();
    const data = {
      conversationId,
      messageId,
      senderName,
      messageText,
      timestamp,
      avatarUrl: avatarUrl || "",
    };

    const failures = [];
    let sent = 0;
    const concurrency = Math.max(1, Math.min(20, Number(req.body?.concurrency) || 10));
    let cursor = 0;

    const worker = async () => {
      while (cursor < targets.length) {
        const current = targets[cursor];
        cursor += 1;
        try {
          await sendFcmDataMessage({ token: current.token, data, accessToken });
          sent += 1;
        } catch (error) {
          failures.push({
            userId: current.userId,
            error: String(error?.message || "unknown_error").slice(0, 500),
          });
        }
      }
    };

    await Promise.all(Array.from({ length: Math.min(concurrency, targets.length) }, () => worker()));

    return res.json({
      ok: failures.length === 0,
      sent,
      failed: failures.length,
      totalTargets: targets.length,
      conversationId,
      messageId,
      failures: failures.slice(0, 25),
    });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Gagal broadcast push chat." });
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
    const familyCtx = await resolveFamilyContext(userId);
    const targetUserId = familyCtx.inFamily ? familyCtx.ownerId : userId;

    const rows = await supabaseRestFetch(
      `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(targetUserId)}&select=accounting_data,data_version,updated_at`
    );
    const snapshot = firstRow(rows);
    const { mirrored } = await ensureCategoryMasterAndMirrorSnapshot(targetUserId, snapshot?.accounting_data || {});
    await supabaseRestFetch(`${FINANCE_TABLE}?on_conflict=user_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify([
        {
          user_id: targetUserId,
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
    const familyCtx = await resolveFamilyContext(userId);
    const targetUserId = familyCtx.inFamily ? familyCtx.ownerId : userId;
    const accountingData = normalizeAccountingData(req.body?.accountingData || req.body?.accounting_data || {});

    // Enforce permissions for family members
    if (familyCtx.inFamily && !familyCtx.isOwner) {
      const oldRows = await supabaseRestFetch(
        `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(targetUserId)}&select=accounting_data`
      ).catch(() => null);
      const oldSnapshot = firstRow(oldRows)?.accounting_data || {};
      const validation = validateSnapshotPermissions(oldSnapshot, accountingData, familyCtx.permissions);
      if (!validation.ok) {
        return res.status(403).json({ error: validation.error });
      }
    }

    await upsertMasterCategories(
      targetUserId,
      collectCategorySeedsFromSnapshot(accountingData).map((item) => ({ ...item, source: "snapshot_sync" }))
    );
    const { mirrored } = await ensureCategoryMasterAndMirrorSnapshot(targetUserId, accountingData);
    const dataVersion = Date.now();
    await supabaseRestFetch(`${FINANCE_TABLE}?on_conflict=user_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify([
        {
          user_id: targetUserId,
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
    const familyCtx = await resolveFamilyContext(userId);
    const targetUserId = familyCtx.inFamily ? familyCtx.ownerId : userId;

    const includeArchived = String(req.query.include_archived || "false").toLowerCase() === "true";
    let categories = await readUserMasterCategories(targetUserId, includeArchived);
    if (!categories.length) {
      const snapshotRows = await supabaseRestFetch(
        `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(targetUserId)}&select=accounting_data`
      );
      const snapshot = firstRow(snapshotRows);
      await ensureCategoryMasterAndMirrorSnapshot(targetUserId, snapshot?.accounting_data || {});
      categories = await readUserMasterCategories(targetUserId, includeArchived);
    }
    return res.json({ categories });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to list categories." });
  }
});

app.post("/api/categories", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const familyCtx = await resolveFamilyContext(userId);
    const targetUserId = familyCtx.inFamily ? familyCtx.ownerId : userId;

    if (familyCtx.inFamily && !familyCtx.permissions.can_edit) {
      return res.status(403).json({ error: "Anda tidak memiliki izin untuk menambah kategori keluarga." });
    }

    const categoryType = normalizeCategoryType(req.body?.category_type || req.body?.type || req.body?.section);
    const name = normalizeCategoryName(req.body?.name);
    if (!categoryType || !name) {
      return res.status(400).json({ error: "category_type dan name wajib diisi." });
    }

    const rows = await upsertMasterCategories(targetUserId, [
      {
        category_type: categoryType,
        name,
        source: req.body?.source || "manual",
      },
    ]);

    const snapshotRows = await supabaseRestFetch(
      `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(targetUserId)}&select=accounting_data,data_version`
    );
    const snapshot = firstRow(snapshotRows);
    const { mirrored } = await ensureCategoryMasterAndMirrorSnapshot(targetUserId, snapshot?.accounting_data || {});
    await supabaseRestFetch(`${FINANCE_TABLE}?on_conflict=user_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify([
        {
          user_id: targetUserId,
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
    const familyCtx = await resolveFamilyContext(userId);
    const targetUserId = familyCtx.inFamily ? familyCtx.ownerId : userId;

    if (familyCtx.inFamily && !familyCtx.permissions.can_edit) {
      return res.status(403).json({ error: "Anda tidak memiliki izin untuk mengubah kategori keluarga." });
    }

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
      `${CATEGORY_TABLE}?id=eq.${encodeURIComponent(id)}&user_id=eq.${encodeURIComponent(targetUserId)}&select=id,user_id,category_type,name,normalized_name,is_archived,source,created_at,updated_at`,
      {
        method: "PATCH",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify(patch),
      }
    );
    const category = firstRow(rows);
    if (!category) return res.status(404).json({ error: "Category tidak ditemukan." });

    const snapshotRows = await supabaseRestFetch(
      `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(targetUserId)}&select=accounting_data,data_version`
    );
    const snapshot = firstRow(snapshotRows);
    const { mirrored } = await ensureCategoryMasterAndMirrorSnapshot(targetUserId, snapshot?.accounting_data || {});
    await supabaseRestFetch(`${FINANCE_TABLE}?on_conflict=user_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify([
        {
          user_id: targetUserId,
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
    const familyCtx = await resolveFamilyContext(userId);
    const targetUserId = familyCtx.inFamily ? familyCtx.ownerId : userId;

    if (familyCtx.inFamily && !familyCtx.permissions.can_edit) {
      return res.status(403).json({ error: "Anda tidak memiliki izin untuk mengarsipkan kategori keluarga." });
    }

    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ error: "Category id wajib diisi." });

    const rows = await supabaseRestFetch(
      `${CATEGORY_TABLE}?id=eq.${encodeURIComponent(id)}&user_id=eq.${encodeURIComponent(targetUserId)}&select=id,user_id,category_type,name,normalized_name,is_archived,source,created_at,updated_at`,
      {
        method: "PATCH",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({ is_archived: true, updated_at: new Date().toISOString() }),
      }
    );
    const category = firstRow(rows);
    if (!category) return res.status(404).json({ error: "Category tidak ditemukan." });

    const snapshotRows = await supabaseRestFetch(
      `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(targetUserId)}&select=accounting_data,data_version`
    );
    const snapshot = firstRow(snapshotRows);
    const { mirrored } = await ensureCategoryMasterAndMirrorSnapshot(targetUserId, snapshot?.accounting_data || {});
    await supabaseRestFetch(`${FINANCE_TABLE}?on_conflict=user_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify([
        {
          user_id: targetUserId,
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
    const familyCtx = await resolveFamilyContext(userId);
    const targetUserId = familyCtx.inFamily ? familyCtx.ownerId : userId;

    if (familyCtx.inFamily && !familyCtx.permissions.can_edit) {
      return res.status(403).json({ error: "Anda tidak memiliki izin untuk mengaktifkan kembali kategori keluarga." });
    }

    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ error: "Category id wajib diisi." });

    const rows = await supabaseRestFetch(
      `${CATEGORY_TABLE}?id=eq.${encodeURIComponent(id)}&user_id=eq.${encodeURIComponent(targetUserId)}&select=id,user_id,category_type,name,normalized_name,is_archived,source,created_at,updated_at`,
      {
        method: "PATCH",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({ is_archived: false, updated_at: new Date().toISOString() }),
      }
    );
    const category = firstRow(rows);
    if (!category) return res.status(404).json({ error: "Category tidak ditemukan." });

    const snapshotRows = await supabaseRestFetch(
      `${FINANCE_TABLE}?user_id=eq.${encodeURIComponent(targetUserId)}&select=accounting_data,data_version`
    );
    const snapshot = firstRow(snapshotRows);
    const { mirrored } = await ensureCategoryMasterAndMirrorSnapshot(targetUserId, snapshot?.accounting_data || {});
    await supabaseRestFetch(`${FINANCE_TABLE}?on_conflict=user_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
      body: JSON.stringify([
        {
          user_id: targetUserId,
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
    const familyCtx = await resolveFamilyContext(userId);
    const targetUserId = familyCtx.inFamily ? familyCtx.ownerId : userId;
    const autoAccess = await resolveAutoTransactionAccess(targetUserId);
    if (!autoAccess.ok) return res.status(403).json({ error: AUTO_TRANSACTION_ACCESS_ERROR });

    const rows = await supabaseRestFetch(
      `${RECURRING_RULE_TABLE}?user_id=eq.${encodeURIComponent(targetUserId)}&order=created_at.desc`
    );
    return res.json({ rules: Array.isArray(rows) ? rows : [] });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to list recurring rules." });
  }
});

app.post("/api/recurring-rules", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const familyCtx = await resolveFamilyContext(userId);
    const targetUserId = familyCtx.inFamily ? familyCtx.ownerId : userId;
    const autoAccess = await resolveAutoTransactionAccess(targetUserId);
    if (!autoAccess.ok) return res.status(403).json({ error: AUTO_TRANSACTION_ACCESS_ERROR });

    if (familyCtx.inFamily && !familyCtx.permissions.can_create) {
      return res.status(403).json({ error: "Anda tidak memiliki izin untuk menambah aturan transaksi berulang." });
    }

    const input = normalizeRecurringRuleInput(req.body || {}, targetUserId, new Date());
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
    const familyCtx = await resolveFamilyContext(userId);
    const targetUserId = familyCtx.inFamily ? familyCtx.ownerId : userId;
    const autoAccess = await resolveAutoTransactionAccess(targetUserId);
    if (!autoAccess.ok) return res.status(403).json({ error: AUTO_TRANSACTION_ACCESS_ERROR });

    if (familyCtx.inFamily && !familyCtx.permissions.can_edit) {
      return res.status(403).json({ error: "Anda tidak memiliki izin untuk mengubah aturan transaksi berulang." });
    }

    if (!ruleId) return res.status(400).json({ error: "rule id is required." });
    const currentRows = await supabaseRestFetch(
      `${RECURRING_RULE_TABLE}?id=eq.${encodeURIComponent(ruleId)}&user_id=eq.${encodeURIComponent(targetUserId)}&select=*`
    );
    const current = Array.isArray(currentRows) ? currentRows[0] : currentRows;
    if (!current) return res.status(404).json({ error: "Recurring rule not found." });

    const mergedInput = {
      ...current,
      ...req.body,
    };
    const next = normalizeRecurringRuleInput(mergedInput, targetUserId, new Date());
    const updated = await updateRecurringRuleRow(ruleId, { ...next, user_id: targetUserId });
    return res.json({ rule: updated });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Failed to update recurring rule." });
  }
});

app.delete("/api/recurring-rules/:id", requireSupabaseUser, async (req, res) => {
  try {
    const ruleId = String(req.params.id || "").trim();
    const userId = req.authUser.id;
    const familyCtx = await resolveFamilyContext(userId);
    const targetUserId = familyCtx.inFamily ? familyCtx.ownerId : userId;
    const autoAccess = await resolveAutoTransactionAccess(targetUserId);
    if (!autoAccess.ok) return res.status(403).json({ error: AUTO_TRANSACTION_ACCESS_ERROR });

    if (familyCtx.inFamily && !familyCtx.permissions.can_delete) {
      return res.status(403).json({ error: "Anda tidak memiliki izin untuk menghapus aturan transaksi berulang." });
    }

    if (!ruleId) return res.status(400).json({ error: "rule id is required." });
    await supabaseRestFetch(
      `${RECURRING_RULE_TABLE}?id=eq.${encodeURIComponent(ruleId)}&user_id=eq.${encodeURIComponent(targetUserId)}`,
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
    const familyCtx = await resolveFamilyContext(userId);
    const targetUserId = familyCtx.inFamily ? familyCtx.ownerId : userId;
    const autoAccess = await resolveAutoTransactionAccess(targetUserId);
    if (!autoAccess.ok) return res.status(403).json({ error: AUTO_TRANSACTION_ACCESS_ERROR });

    const limit = Math.min(200, Math.max(1, Number(req.query.limit || 50)));
    const rows = await supabaseRestFetch(
      `${RECURRING_RUN_TABLE}?user_id=eq.${encodeURIComponent(targetUserId)}&order=created_at.desc&limit=${limit}`
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
    const familyCtx = await resolveFamilyContext(userId);
    const targetUserId = familyCtx.inFamily ? familyCtx.ownerId : userId;
    const autoAccess = await resolveAutoTransactionAccess(targetUserId);
    if (!autoAccess.ok) return res.status(403).json({ error: AUTO_TRANSACTION_ACCESS_ERROR });

    if (familyCtx.inFamily && !familyCtx.permissions.can_edit) {
      return res.status(403).json({ error: "Anda tidak memiliki izin untuk mensinkronisasi timezone aturan keluarga." });
    }

    const timezoneName = String(req.body?.timezone_name || "").trim();
    if (!ruleId || !timezoneName) {
      return res.status(400).json({ error: "rule id and timezone_name are required." });
    }
    const currentRows = await supabaseRestFetch(
      `${RECURRING_RULE_TABLE}?id=eq.${encodeURIComponent(ruleId)}&user_id=eq.${encodeURIComponent(targetUserId)}&select=*`
    );
    const current = Array.isArray(currentRows) ? currentRows[0] : currentRows;
    if (!current) return res.status(404).json({ error: "Recurring rule not found." });
    const merged = {
      ...current,
      timezone_name: timezoneName,
    };
    const normalized = normalizeRecurringRuleInput(merged, targetUserId, new Date());
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

app.post("/api/family/create", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    
    // 1. Check if user is already in a family
    const familyCtx = await resolveFamilyContext(userId);
    if (familyCtx.inFamily) {
      return res.status(400).json({ error: "Anda sudah terdaftar dalam sebuah keluarga." });
    }

    // 2. Check if eligible (premium subscription / family package)
    const eligible = await canUserCreateFamily(userId);
    if (!eligible) {
      return res.status(403).json({ error: "Akun Anda harus berlangganan paket Family atau Family Pro untuk membuat keluarga." });
    }

    // 3. Generate unique invite code
    let inviteCode = "";
    let attempts = 0;
    while (attempts < 5) {
      const rand = Math.random().toString(36).substring(2, 8).toUpperCase();
      const existing = await supabaseRestFetch(`families?invite_code=eq.${encodeURIComponent(rand)}&select=id&limit=1`).catch(() => null);
      if (!firstRow(existing)) {
        inviteCode = rand;
        break;
      }
      attempts++;
    }
    if (!inviteCode) {
      inviteCode = "FAM" + Math.floor(100 + Math.random() * 900);
    }

    // 4. Insert row
    const payload = {
      owner_id: userId,
      invite_code: inviteCode,
    };
    const createdRows = await supabaseRestFetch("families", {
      method: "POST",
      headers: { Prefer: "return=representation" },
      body: JSON.stringify([payload]),
    });
    const createdFamily = firstRow(createdRows);
    
    return res.json({ ok: true, family: createdFamily });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Gagal membuat keluarga." });
  }
});

app.post("/api/family/join", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const inviteCode = String(req.body?.invite_code || req.body?.inviteCode || "").trim().toUpperCase();
    if (!inviteCode) {
      return res.status(400).json({ error: "Invite code wajib diisi." });
    }

    // 1. Check if user is already in a family
    const familyCtx = await resolveFamilyContext(userId);
    if (familyCtx.inFamily) {
      return res.status(400).json({ error: "Anda sudah terdaftar dalam sebuah keluarga. Silakan keluar terlebih dahulu." });
    }

    // 2. Find family
    const familyRows = await supabaseRestFetch(`families?invite_code=eq.${encodeURIComponent(inviteCode)}&select=id,owner_id`).catch(() => null);
    const family = firstRow(familyRows);
    if (!family) {
      return res.status(404).json({ error: "Kode undangan keluarga tidak ditemukan." });
    }

    if (family.owner_id === userId) {
      return res.status(400).json({ error: "Anda adalah pemilik keluarga ini." });
    }

    // 3. Create family member
    const memberPayload = {
      family_id: family.id,
      user_id: userId,
      role: "member",
      can_create: true,
      can_edit: false,
      can_delete: false,
    };
    const insertedRows = await supabaseRestFetch("family_members", {
      method: "POST",
      headers: { Prefer: "return=representation" },
      body: JSON.stringify([memberPayload]),
    });
    
    return res.json({ ok: true, member: firstRow(insertedRows) });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Gagal bergabung ke keluarga." });
  }
});

app.post("/api/family/leave", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;

    // Check if they are a member
    const memberRows = await supabaseRestFetch(`family_members?user_id=eq.${encodeURIComponent(userId)}&select=id&limit=1`).catch(() => null);
    const member = firstRow(memberRows);
    if (!member) {
      return res.status(400).json({ error: "Anda tidak terdaftar sebagai anggota keluarga manapun." });
    }

    // Delete member row
    await supabaseRestFetch(`family_members?id=eq.${encodeURIComponent(member.id)}`, {
      method: "DELETE",
    });

    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Gagal keluar dari keluarga." });
  }
});

app.post("/api/family/members/:memberId/permissions", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const memberId = String(req.params.memberId || "").trim();
    const { can_create, can_edit, can_delete } = req.body;

    // Check if owner
    const familyRows = await supabaseRestFetch(`families?owner_id=eq.${encodeURIComponent(userId)}&select=id&limit=1`).catch(() => null);
    const family = firstRow(familyRows);
    if (!family) {
      return res.status(403).json({ error: "Hanya pemilik keluarga yang dapat mengatur izin." });
    }

    // Check if member is in family
    const memberRows = await supabaseRestFetch(`family_members?id=eq.${encodeURIComponent(memberId)}&family_id=eq.${encodeURIComponent(family.id)}&select=id`).catch(() => null);
    const member = firstRow(memberRows);
    if (!member) {
      return res.status(404).json({ error: "Anggota tidak ditemukan dalam keluarga Anda." });
    }

    const patch = {};
    if (can_create !== undefined) patch.can_create = !!can_create;
    if (can_edit !== undefined) patch.can_edit = !!can_edit;
    if (can_delete !== undefined) patch.can_delete = !!can_delete;
    patch.updated_at = new Date().toISOString();

    await supabaseRestFetch(`family_members?id=eq.${encodeURIComponent(memberId)}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    });

    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Gagal memperbarui izin anggota." });
  }
});

app.delete("/api/family/members/:memberId", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;
    const memberId = String(req.params.memberId || "").trim();

    // Check if owner
    const familyRows = await supabaseRestFetch(`families?owner_id=eq.${encodeURIComponent(userId)}&select=id&limit=1`).catch(() => null);
    const family = firstRow(familyRows);
    if (!family) {
      return res.status(403).json({ error: "Hanya pemilik keluarga yang dapat mengeluarkan anggota." });
    }

    // Check if member is in family
    const memberRows = await supabaseRestFetch(`family_members?id=eq.${encodeURIComponent(memberId)}&family_id=eq.${encodeURIComponent(family.id)}&select=id`).catch(() => null);
    const member = firstRow(memberRows);
    if (!member) {
      return res.status(404).json({ error: "Anggota tidak ditemukan dalam keluarga Anda." });
    }

    await supabaseRestFetch(`family_members?id=eq.${encodeURIComponent(memberId)}`, {
      method: "DELETE",
    });

    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Gagal mengeluarkan anggota." });
  }
});

app.delete("/api/family/delete", requireSupabaseUser, async (req, res) => {
  try {
    const userId = req.authUser.id;

    // Check if owner
    const familyRows = await supabaseRestFetch(`families?owner_id=eq.${encodeURIComponent(userId)}&select=id&limit=1`).catch(() => null);
    const family = firstRow(familyRows);
    if (!family) {
      return res.status(404).json({ error: "Anda tidak memiliki keluarga aktif untuk dihapus." });
    }

    await supabaseRestFetch(`families?id=eq.${encodeURIComponent(family.id)}`, {
      method: "DELETE",
    });

    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: error?.message || "Gagal membubarkan keluarga." });
  }
});

app.post("/api/agent/actions", async (req, res) => {
  const started = Date.now();
  let safePrompt = "";
  try {
    const { currentData, language, accessPlan: clientAccessPlan } = req.body || {};
    // Server-side subscription verification: get userId from JWT if present
    let accessPlan = clientAccessPlan || "free";
    let userId = null;
    const bearerToken = getBearerTokenFromRequest(req);
    if (bearerToken) {
      try {
        const authUser = await verifySupabaseUserAccessToken(bearerToken);
        if (authUser?.id) {
          userId = authUser.id;
          const dbPlan = await resolveUserAccessPlanFromDB(authUser.id);
          if (dbPlan !== null) accessPlan = dbPlan;
        }
      } catch (_authErr) { /* non-authed request, use client value */ }
    }
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
    const modelPolicy = resolveAiRouteModelPolicy({
      route: "agent_actions",
      prompt: safePrompt,
      accessPlan,
    });
    logAiRoute("/api/agent/actions", {
      accessPlan: accessPlan || "free",
      inputChars: safePrompt.length,
      plan_tier: modelPolicy.planTier,
      model: modelPolicy.primaryModel,
      model_primary: modelPolicy.primaryModel,
      model_fallback_chain: modelPolicy.fallbackModels,
    });
    const compactData = buildCompactData(currentData || {});
    const actionSystem = buildActionSystemInstruction(targetLanguage, compactData);
    const messages = buildOpenRouterMessages(
      actionSystem,
      req.body.history,
      safePrompt,
      req.body.replyTo
    );

    let usedModel = modelPolicy.primaryModel;
    let fallbackUsed = false;
    let retryForced = false;
    let result = { actions: [], assistantText: "" };
    let lastRouteError = null;
    const modelAttempts = [];
    for (let idx = 0; idx < modelPolicy.modelFallbackChain.length; idx += 1) {
      const candidateModel = modelPolicy.modelFallbackChain[idx];
      const candidateTimeout = idx === 0 ? modelPolicy.primaryTimeout : modelPolicy.secondaryTimeout;
      try {
        let candidateResult = await callOpenRouterActions({
          model: candidateModel,
          timeoutMs: candidateTimeout,
          messages,
          referer: req.headers.referer,
          toolChoice: "auto",
        });

        if (!candidateResult.actions.length) {
          retryForced = true;
          candidateResult = await callOpenRouterActions({
            model: candidateModel,
            timeoutMs: candidateTimeout,
            messages,
            referer: req.headers.referer,
            toolChoice: "required",
          });
        }

        if (candidateResult.actions.length) {
          usedModel = candidateModel;
          fallbackUsed = idx > 0;
          result = candidateResult;
          modelAttempts.push({ model: candidateModel, ok: true, phase: "actions" });
          break;
        }

        usedModel = candidateModel;
        fallbackUsed = idx > 0;
        modelAttempts.push({ model: candidateModel, ok: false, reason: "no_actions" });
      } catch (candidateError) {
        lastRouteError = candidateError;
        usedModel = candidateModel;
        fallbackUsed = idx > 0;
        modelAttempts.push({
          model: candidateModel,
          ok: false,
          reason: getAiErrorCode(candidateError),
          retriable: isRetriableAiError(candidateError),
        });
        if (!isRetriableAiError(candidateError)) break;
      }
    }

    if (!result.actions.length && lastRouteError) throw lastRouteError;

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
          model_attempts: modelAttempts,
          total_ms: Date.now() - started,
        },
      });
    }

    result.actions = await validateTransactionClassifications({
      prompt: safePrompt,
      actions: result.actions,
      model: usedModel,
      timeoutMs: Math.min(modelPolicy.primaryTimeout, modelPolicy.secondaryTimeout),
      referer: req.headers.referer,
    });

    cleanupExpiredActionConfirmations();
    const filteredActions = (Array.isArray(result.actions) ? result.actions : []).filter((action) =>
      isAllowedAgentAction(action)
    );
    const droppedCount = (Array.isArray(result.actions) ? result.actions.length : 0) - filteredActions.length;

    const hasTransactionAction = filteredActions.some((action) =>
      ["addTransaction", "createTransaction", "updateTransaction", "deleteTransaction", "bulkUpdateTransactions", "bulkDeleteTransactions"].includes(
        String(action?.name || "")
      )
    );
    const candidates = hasTransactionAction && isInvestmentPrompt(safePrompt)
      ? findRelatedEntityCandidates(currentData || {}, safePrompt)
      : [];

    const selectionRequests = [];
    if (candidates.length && hasTransactionAction) {
      const matched = candidates[0];
      const selectionId = `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
      const txAmount = getFirstTransactionAmount(filteredActions);
      const relateActions = [...filteredActions];
      if (matched.type === "tabungan" && txAmount > 0) {
        relateActions.push({
          name: "addTabungan",
          args: {
            name: matched.name,
            amount: txAmount,
            note: "Catatan tambahan dari pilihan AI",
            account: "Total Keuangan",
          },
        });
      }

      await savePendingAction(selectionId, userId, "selection", {
        context: {
          matchedEntity: matched,
          candidates,
        },
        options: {
          apply_related: {
            actions: relateActions,
            assistantText: `Siap, transaksi akan dikaitkan ke ${matched.type} "${matched.name}".`,
          },
          transaction_only: {
            actions: filteredActions,
            assistantText: "Siap, saya catat sebagai transaksi saja.",
          },
          cancel: {
            actions: [],
            assistantText: "Oke, tidak ada perubahan data.",
          },
        },
      });

      selectionRequests.push({
        id: selectionId,
        title: "Pilih Cara Pencatatan",
        message: `Saya menemukan ${matched.type} terkait: "${matched.name}". Mau lanjut bagaimana?`,
        matchedEntity: matched,
        candidates,
        options: [
          { id: "apply_related", label: "Catat ke tabungan/budget terkait", description: "Transaksi + kaitkan ke target terkait", value: "apply_related" },
          { id: "transaction_only", label: "Hanya catat transaksi", description: "Simpan transaksi saja", value: "transaction_only" },
          { id: "cancel", label: "Batal", description: "Tidak ada perubahan data", value: "cancel" },
        ],
      });
    }

    const directActions = [];
    const confirmationActions = [];
    if (!selectionRequests.length) {
      for (const action of filteredActions) {
        if (isConfirmationRequiredAction(action)) {
          confirmationActions.push(action);
        } else {
          directActions.push(action);
        }
      }
    }

    const confirmationRequests = [];
    if (confirmationActions.length) {
      const confirmationId = `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
      const summary = buildConfirmationRequestMessage(confirmationActions);
      await savePendingAction(confirmationId, userId, "confirmation", {
        actions: confirmationActions,
        summary,
      });
      confirmationRequests.push({
        id: confirmationId,
        title: "Konfirmasi Perubahan Data",
        message: summary,
        summary,
        actions: confirmationActions,
        kind: "mutating",
      });
    }

    return res.json({
      ok: true,
      actions: directActions,
      confirmationRequests,
      selectionRequests,
      assistantText:
        selectionRequests.length
          ? "Saya butuh pilihan kamu dulu sebelum mengeksekusi aksi."
          : result.assistantText?.trim() ||
            (confirmationRequests.length
              ? "Perintah siap. Ada perubahan data yang menunggu konfirmasi kamu."
              : "Siap, perubahan data keuangan sudah saya susun."),
      metadata: {
        processing_mode: "ai_actions",
        model_used: usedModel,
        model_primary: modelPolicy.primaryModel,
        model_fallback_chain: modelPolicy.fallbackModels,
        plan_tier: modelPolicy.planTier,
        final_model_used: usedModel,
        fallback_used: fallbackUsed,
        model_attempts: modelAttempts,
        retry_forced_tool_choice: retryForced,
        dropped_actions: droppedCount,
        total_ms: Date.now() - started,
      },
    });
  } catch (error) {
    const errorCode = getAiErrorCode(error);
    if (errorCode !== "unknown") {
      const status = errorCode === "rate_limited" ? 429 : 503;
      console.warn("Agent Actions AI Error:", {
        error_code: errorCode,
        message: error?.message || error,
      });
      return res.status(status).json({
        ok: false,
        actions: [],
        assistantText: "",
        error: getAiUserFacingMessage(error),
        error_code: errorCode,
        error_domain: "ai_provider_error",
        error_phase: "agent_actions_generation",
      });
    }
    console.error("Agent Actions Error:", error);
    return res.status(500).json({
      ok: false,
      actions: [],
      assistantText: "",
      error: error?.message || "Agent action request failed.",
      error_code: "unknown",
      error_domain: "agent_actions_error",
      error_phase: "agent_actions_generation",
    });
  }
});

app.post("/api/agent/actions/confirm", async (req, res) => {
  try {
    const { confirmationId } = req.body || {};
    const id = String(confirmationId || "").trim();
    if (!id) {
      console.warn("[confirm-pipeline]", JSON.stringify({ status: "confirmed_failed", confirmation_id: id || null, error_code: "missing_confirmation_id" }));
      return res.status(400).json({
        ok: false,
        error: "confirmationId wajib diisi.",
        error_code: "missing_confirmation_id",
        error_domain: "confirm_error",
      });
    }
    const userId = await getUserIdFromRequest(req);
    cleanupExpiredActionConfirmations();
    const pending = await getPendingAction(id, userId, 'confirmation');
    if (!pending) {
      console.warn("[confirm-pipeline]", JSON.stringify({ status: "confirmed_failed", confirmation_id: id, error_code: "confirmation_not_found" }));
      return res.status(404).json({
        ok: false,
        error: "Konfirmasi tidak ditemukan atau kadaluarsa.",
        error_code: "confirmation_not_found",
        error_domain: "confirm_error",
      });
    }
    await deletePendingAction(id, userId, 'confirmation');
    console.log(
      "[confirm-pipeline]",
      JSON.stringify({
        status: "confirmed_applied",
        confirmation_id: id,
        action_count: Array.isArray(pending.actions) ? pending.actions.length : 0,
      })
    );

    return res.json({
      ok: true,
      actions: Array.isArray(pending.actions) ? pending.actions : [],
      recurringActions: Array.isArray(pending.actions) ? pending.actions : [],
      updatedData: null,
      notices: [],
      actionSummaries: [],
      metrics: null,
      metadata: {
        confirmation_id: id,
        status: "confirmed_applied",
        uses_client_local_data: true,
      },
    });
  } catch (error) {
    const confirmationId = String(req.body?.confirmationId || "").trim() || null;
    const aiCode = getAiErrorCode(error);
    const errorCode = aiCode && aiCode !== "unknown" ? aiCode : "confirm_processing_failed";
    const errorDomain = aiCode && aiCode !== "unknown" ? "ai_provider_error" : "confirm_error";
    console.warn("[confirm-pipeline]", JSON.stringify({ status: "confirmed_failed", confirmation_id: confirmationId, error_code: errorCode }));
    return res.status(500).json({
      ok: false,
      error: error?.message || "Gagal memproses konfirmasi aksi.",
      error_code: errorCode,
      error_domain: errorDomain,
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
    const userId = await getUserIdFromRequest(req);
    await deletePendingAction(id, userId, 'confirmation');
    return res.json({ ok: true, cancelled: true });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      error: error?.message || "Gagal membatalkan konfirmasi aksi.",
    });
  }
});

app.post("/api/agent/actions/select", async (req, res) => {
  try {
    const { selectionId, optionId } = req.body || {};
    const id = String(selectionId || "").trim();
    const option = String(optionId || "").trim();
    if (!id || !option) {
      return res.status(400).json({ ok: false, error: "selectionId dan optionId wajib diisi." });
    }
    const userId = await getUserIdFromRequest(req);
    cleanupExpiredActionConfirmations();
    const pending = await getPendingAction(id, userId, 'selection');
    if (!pending) {
      return res.status(404).json({ ok: false, error: "Pilihan tidak ditemukan atau kadaluarsa." });
    }
    const selected = pending?.options?.[option];
    if (!selected) {
      return res.status(400).json({ ok: false, error: "Opsi pilihan tidak valid." });
    }
    await deletePendingAction(id, userId, 'selection');

    const actions = Array.isArray(selected.actions)
      ? selected.actions.filter((action) => isAllowedAgentAction(action))
      : [];
    if (!actions.length) {
      return res.json({
        ok: true,
        actions: [],
        confirmationRequests: [],
        assistantText: selected.assistantText || "Tidak ada perubahan data.",
      });
    }

    const confirmationId = `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
    const summary = buildConfirmationRequestMessage(actions);
    await savePendingAction(confirmationId, userId, "confirmation", {
      actions,
      summary,
    });
    return res.json({
      ok: true,
      actions: [],
      confirmationRequests: [
        {
          id: confirmationId,
          title: "Konfirmasi Perubahan Data",
          message: summary,
          summary,
          actions,
          kind: "mutating",
        },
      ],
      assistantText: selected.assistantText || "Pilihan diterima. Lanjut konfirmasi dulu ya.",
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      error: error?.message || "Gagal memproses pilihan.",
    });
  }
});

app.post("/api/chat", async (req, res) => {
  const started = Date.now();
  let prompt = "";
  try {
    const { currentData, language, accessPlan: clientAccessPlan } = req.body || {};
    // Server-side subscription verification
    let accessPlan = clientAccessPlan || "free";
    const bearerToken = getBearerTokenFromRequest(req);
    if (bearerToken) {
      try {
        const authUser = await verifySupabaseUserAccessToken(bearerToken);
        if (authUser?.id) {
          const dbPlan = await resolveUserAccessPlanFromDB(authUser.id);
          if (dbPlan !== null) accessPlan = dbPlan;
        }
      } catch (_authErr) { /* non-authed request, use client value */ }
    }
    try {
      prompt = ensurePromptPayload(req.body || {});
    } catch (error) {
      return res.status(400).json({ error: error?.message || "Payload tidak valid." });
    }
    const targetLanguage = language || "Indonesian";
    const modelPolicy = resolveAiRouteModelPolicy({
      route: "chat",
      prompt: prompt || "",
      accessPlan,
    });
    const intent = modelPolicy.intent;
    logAiRoute("/api/chat", {
      accessPlan: accessPlan || "free",
      intent,
      inputChars: String(prompt || "").length,
      plan_tier: modelPolicy.planTier,
      model: modelPolicy.primaryModel,
      model_primary: modelPolicy.primaryModel,
      model_fallback_chain: modelPolicy.fallbackModels,
    });
    const compactData = buildCompactData(currentData || {});
    const systemInstruction = buildSystemInstruction(targetLanguage, compactData);
    const messages = buildOpenRouterMessages(
      systemInstruction,
      req.body.history,
      prompt,
      req.body.replyTo
    );

    let usedModel = modelPolicy.primaryModel;
    let fallbackUsed = false;
    let aiText = "";
    let timing = { ttftMs: 0, totalMs: 0 };
    let lastRouteError = null;
    const modelAttempts = [];
    for (let idx = 0; idx < modelPolicy.modelFallbackChain.length; idx += 1) {
      const candidateModel = modelPolicy.modelFallbackChain[idx];
      const candidateTimeout = idx === 0 ? modelPolicy.primaryTimeout : modelPolicy.secondaryTimeout;
      const candidateMaxTokens = idx === 0 ? modelPolicy.maxTokens : Math.max(modelPolicy.maxTokens, 400);
      try {
        const result = await callOpenRouterText({
          model: candidateModel,
          timeoutMs: candidateTimeout,
          messages,
          maxTokens: candidateMaxTokens,
          referer: req.headers.referer,
        });
        usedModel = candidateModel;
        fallbackUsed = idx > 0;
        aiText = result.text;
        timing = { ttftMs: result.ttftMs, totalMs: result.totalMs };
        modelAttempts.push({ model: candidateModel, ok: true });
        if (idx > 0) {
          console.warn("Primary model failed, fallback used:", String(lastRouteError || ""));
        }
        break;
      } catch (candidateError) {
        lastRouteError = candidateError;
        modelAttempts.push({
          model: candidateModel,
          ok: false,
          reason: getAiErrorCode(candidateError),
          retriable: isRetriableAiError(candidateError),
        });
        if (!isRetriableAiError(candidateError)) break;
      }
    }
    if (!aiText && lastRouteError) throw lastRouteError;

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
        model_primary: modelPolicy.primaryModel,
        model_fallback_chain: modelPolicy.fallbackModels,
        plan_tier: modelPolicy.planTier,
        final_model_used: usedModel,
        fallback_used: fallbackUsed,
        model_attempts: modelAttempts,
        ttft_ms: timing.ttftMs,
        total_ms: Date.now() - started,
      },
    });
  } catch (error) {
    if (getAiErrorCode(error) !== "unknown") {
      const status = getAiErrorCode(error) === "rate_limited" ? 429 : 503;
      return res.status(status).json({
        error: getAiUserFacingMessage(error),
        error_code: getAiErrorCode(error),
      });
    }
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
    const { currentData, language, accessPlan: clientAccessPlan } = req.body || {};
    // Server-side subscription verification
    let accessPlan = clientAccessPlan || "free";
    const bearerToken = getBearerTokenFromRequest(req);
    if (bearerToken) {
      try {
        const authUser = await verifySupabaseUserAccessToken(bearerToken);
        if (authUser?.id) {
          const dbPlan = await resolveUserAccessPlanFromDB(authUser.id);
          if (dbPlan !== null) accessPlan = dbPlan;
        }
      } catch (_authErr) { /* non-authed request, use client value */ }
    }
    try {
      prompt = ensurePromptPayload(req.body || {});
    } catch (error) {
      res.status(400).json({ error: error?.message || "Payload tidak valid." });
      return;
    }
    const targetLanguage = language || "Indonesian";
    const modelPolicy = resolveAiRouteModelPolicy({
      route: "chat_stream",
      prompt: prompt || "",
      accessPlan,
    });
    const intent = modelPolicy.intent;
    logAiRoute("/api/chat/stream", {
      accessPlan: accessPlan || "free",
      intent,
      inputChars: String(prompt || "").length,
      plan_tier: modelPolicy.planTier,
      model: modelPolicy.primaryModel,
      model_primary: modelPolicy.primaryModel,
      model_fallback_chain: modelPolicy.fallbackModels,
    });
    const compactData = buildCompactData(currentData || {});
    const systemInstruction = buildSystemInstruction(targetLanguage, compactData);
    const messages = buildOpenRouterMessages(
      systemInstruction,
      req.body.history,
      prompt,
      req.body.replyTo
    );

    res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    let usedModel = modelPolicy.primaryModel;
    let fallbackUsed = false;
    let fullText = "";
    let hasEmittedToken = false;
    let ttftMs = 0;
    const modelAttempts = [];

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

    let lastRouteError = null;
    for (let idx = 0; idx < modelPolicy.modelFallbackChain.length; idx += 1) {
      const candidateModel = modelPolicy.modelFallbackChain[idx];
      const candidateTimeout = idx === 0 ? modelPolicy.primaryTimeout : modelPolicy.secondaryTimeout;
      const candidateMaxTokens = idx === 0 ? modelPolicy.maxTokens : Math.max(modelPolicy.maxTokens, 400);
      try {
        usedModel = candidateModel;
        fallbackUsed = idx > 0;
        await runStream(candidateModel, candidateTimeout, candidateMaxTokens);
        modelAttempts.push({ model: candidateModel, ok: true });
        if (idx > 0) {
          console.warn("Primary stream failed, fallback used:", String(lastRouteError || ""));
        }
        break;
      } catch (candidateError) {
        if (hasEmittedToken) throw candidateError;
        lastRouteError = candidateError;
        modelAttempts.push({
          model: candidateModel,
          ok: false,
          reason: getAiErrorCode(candidateError),
          retriable: isRetriableAiError(candidateError),
        });
        if (!isRetriableAiError(candidateError)) break;
      }
    }
    if (!fullText && lastRouteError) throw lastRouteError;

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
        model_primary: modelPolicy.primaryModel,
        model_fallback_chain: modelPolicy.fallbackModels,
        plan_tier: modelPolicy.planTier,
        final_model_used: usedModel,
        fallback_used: fallbackUsed,
        model_attempts: modelAttempts,
        ttft_ms: ttftMs,
        total_ms: Date.now() - started,
      },
    });
    res.end();
  } catch (error) {
    if (getAiErrorCode(error) !== "unknown") {
      sendEvent("error", { message: getAiUserFacingMessage(error), error_code: getAiErrorCode(error) });
      res.end();
      return;
    }
    console.error("AI Stream Error:", error);
    sendEvent("error", { message: error?.message || "Streaming failed" });
    res.end();
  }
});

app.post("/api/quick-suggestions", async (req, res) => {
  try {
    const { text, language, accessPlan: clientAccessPlan } = req.body || {};
    // Server-side subscription verification
    let accessPlan = clientAccessPlan || "free";
    const bearerToken = getBearerTokenFromRequest(req);
    if (bearerToken) {
      try {
        const authUser = await verifySupabaseUserAccessToken(bearerToken);
        if (authUser?.id) {
          const dbPlan = await resolveUserAccessPlanFromDB(authUser.id);
          if (dbPlan !== null) accessPlan = dbPlan;
        }
      } catch (_authErr) { /* non-authed request */ }
    }
    const query = String(text || "").trim();
    if (!query) return res.json({ suggestions: [] });
    if (query.length > MAX_PROMPT_CHARS) {
      return res.status(400).json({ error: `Input terlalu panjang. Maksimal ${MAX_PROMPT_CHARS} karakter.` });
    }

    const prompt = `User is typing this request: "${query}".
Generate exactly 3 short quick suggestions for a personal finance assistant app.
Rules:
- Language: ${language || "Indonesian"}
- Each suggestion must be max 40 characters
- Practical and directly actionable
- No numbering, no markdown, no explanation
- Return valid JSON object only: {"suggestions":["...","...","..."]}`;
    const modelPolicy = resolveAiRouteModelPolicy({
      route: "quick_suggestions",
      prompt: query,
      accessPlan,
    });
    let usedModel = modelPolicy.primaryModel;
    let fallbackUsed = false;
    logAiRoute("/api/quick-suggestions", {
      accessPlan: accessPlan || "free",
      inputChars: query.length,
      plan_tier: modelPolicy.planTier,
      model: modelPolicy.primaryModel,
      model_primary: modelPolicy.primaryModel,
      model_fallback_chain: modelPolicy.fallbackModels,
    });

    let result = null;
    let lastRouteError = null;
    const modelAttempts = [];
    for (let idx = 0; idx < modelPolicy.modelFallbackChain.length; idx += 1) {
      const candidateModel = modelPolicy.modelFallbackChain[idx];
      try {
        result = await callOpenRouterText({
          model: candidateModel,
          timeoutMs: 12000,
          maxTokens: 120,
          referer: req.headers.referer,
          messages: [{ role: "user", content: prompt }],
        });
        usedModel = candidateModel;
        fallbackUsed = idx > 0;
        modelAttempts.push({ model: candidateModel, ok: true });
        break;
      } catch (candidateError) {
        lastRouteError = candidateError;
        modelAttempts.push({
          model: candidateModel,
          ok: false,
          reason: getAiErrorCode(candidateError),
          retriable: isRetriableAiError(candidateError),
        });
        if (!isRetriableAiError(candidateError)) break;
      }
    }
    if (!result && lastRouteError) throw lastRouteError;

    let parsed = null;
    const textResult = String(result?.text || "").trim();
    try {
      parsed = JSON.parse(textResult);
    } catch {
      const match = textResult.match(/\{[\s\S]*\}/);
      if (match) parsed = JSON.parse(match[0]);
    }

    const suggestions = Array.isArray(parsed?.suggestions)
      ? parsed.suggestions
          .map((v) => String(v || "").trim().slice(0, 40))
          .filter(Boolean)
          .slice(0, 3)
      : [];

    if (!suggestions.length) throw new Error("No suggestions returned");
    return res.json({
      suggestions,
      metadata: {
        model_used: usedModel,
        model_primary: modelPolicy.primaryModel,
        model_fallback_chain: modelPolicy.fallbackModels,
        plan_tier: modelPolicy.planTier,
        final_model_used: usedModel,
        fallback_used: fallbackUsed,
        model_attempts: modelAttempts,
      },
    });
  } catch (error) {
    if (getAiErrorCode(error) !== "unknown") {
      const status = getAiErrorCode(error) === "rate_limited" ? 429 : 503;
      return res.status(status).json({ error: getAiUserFacingMessage(error), error_code: getAiErrorCode(error) });
    }
    return res.status(503).json({ error: error?.message || "Quick suggestions unavailable" });
  }
});

app.post("/api/report/recommendations", async (req, res) => {
  const started = Date.now();
  try {
    const { currentData, language, accessPlan: clientAccessPlan } = req.body || {};
    const targetLanguage = String(language || "Indonesian");
    if (!currentData || typeof currentData !== "object") {
      return res.status(400).json({ error: "Missing currentData." });
    }

    // Server-side subscription verification
    let accessPlan = clientAccessPlan || "free";
    const bearerToken = getBearerTokenFromRequest(req);
    if (bearerToken) {
      try {
        const authUser = await verifySupabaseUserAccessToken(bearerToken);
        if (authUser?.id) {
          const dbPlan = await resolveUserAccessPlanFromDB(authUser.id);
          if (dbPlan !== null) accessPlan = dbPlan;
        }
      } catch (_authErr) { /* non-authed request */ }
    }

    const modelPolicy = resolveAiRouteModelPolicy({
      route: "report_recommendations",
      prompt: JSON.stringify(currentData || {}).slice(0, 4000),
      accessPlan,
    });
    let usedModel = modelPolicy.primaryModel;
    let fallbackUsed = false;

    logAiRoute("/api/report/recommendations", {
      accessPlan: accessPlan || "free",
      plan_tier: modelPolicy.planTier,
      model: modelPolicy.primaryModel,
      model_primary: modelPolicy.primaryModel,
      model_fallback_chain: modelPolicy.fallbackModels,
    });

    let result = null;
    let lastRouteError = null;
    const modelAttempts = [];
    for (let idx = 0; idx < modelPolicy.modelFallbackChain.length; idx += 1) {
      const candidateModel = modelPolicy.modelFallbackChain[idx];
      try {
        result = await callOpenRouterText({
          model: candidateModel,
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
        usedModel = candidateModel;
        fallbackUsed = idx > 0;
        modelAttempts.push({ model: candidateModel, ok: true });
        break;
      } catch (candidateError) {
        lastRouteError = candidateError;
        modelAttempts.push({
          model: candidateModel,
          ok: false,
          reason: getAiErrorCode(candidateError),
          retriable: isRetriableAiError(candidateError),
        });
        if (!isRetriableAiError(candidateError)) break;
      }
    }
    if (!result && lastRouteError) throw lastRouteError;

    const aiResult = parseReportAiResult(result?.text);
    if (!aiResult.recommendations.length && aiResult.healthScore === null) {
      throw new Error("No report AI result returned");
    }

    return res.json({
      recommendations: aiResult.recommendations,
      healthScore: aiResult.healthScore,
      healthStatus: aiResult.healthStatus,
      metadata: {
        processing_mode: "report_recommendation",
        model_used: usedModel,
        model_primary: modelPolicy.primaryModel,
        model_fallback_chain: modelPolicy.fallbackModels,
        plan_tier: modelPolicy.planTier,
        final_model_used: usedModel,
        fallback_used: fallbackUsed,
        model_attempts: modelAttempts,
        ttft_ms: result?.ttftMs,
        total_ms: Date.now() - started,
      },
    });
  } catch (error) {
    if (getAiErrorCode(error) !== "unknown") {
      const status = getAiErrorCode(error) === "rate_limited" ? 429 : 503;
      return res.status(status).json({
        error: getAiUserFacingMessage(error),
        error_code: getAiErrorCode(error),
      });
    }
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
