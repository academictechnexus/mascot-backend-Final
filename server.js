// server.js
// Full-featured mascot chatbot backend (updated: trust-proxy + robust IPv4 DB resolution via resolve4 -> lookup -> DoH)
// - Multi-tenant (sites table)
// - Plans: basic / pro / advanced (RAG, summaries)
// - Usage quotas (daily)
// - Conversation & messages storage
// - RAG context (knowledge_items)
// - OpenAI Chat integration (axios)
// - Upload endpoint (multer)
// - Diagnostics: /health, /health-db, /openai/ping
// - CORS, helmet, rate-limit, morgan
// - Demo auto-create for demo-basic / demo-pro / demo-advanced
// Keep this file updated and ensure env vars are set: DATABASE_URL, OPENAI_API_KEY

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const axios = require("axios");
const morgan = require("morgan");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const dns = require("dns").promises;
const { URL } = require("url");
require("dotenv").config();

// ---------- Config ----------
const app = express();

// Trust proxy headers (fixes express-rate-limit X-Forwarded-For validation behind proxies/CDNs)
app.set("trust proxy", true);

const PORT = process.env.PORT || 8080;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const DATABASE_URL = process.env.DATABASE_URL || "";

if (!DATABASE_URL) {
  console.warn("⚠️ DATABASE_URL not set — server will proceed but DB calls will fail.");
}

// ---------- DB init (robust IPv4 resolution: resolve4 -> lookup family:4 -> DoH dns.google) ----------
let pool = null;

// lightweight db wrapper used by routes; will delegate to `pool` once ready.
const db = {
  query: (text, params) => {
    if (!pool) throw new Error("Postgres pool not initialized yet");
    return pool.query(text, params);
  },
};

(async function initPostgresPool() {
  try {
    if (!DATABASE_URL) {
      console.warn("⚠️ DATABASE_URL not set — pool cannot be created.");
      return;
    }

    const parsed = new URL(DATABASE_URL);
    const originalHost = parsed.hostname;
    let ipv4Host = null;

    // 1) Try dns.resolve4 (direct A-record query)
    try {
      const addrs = await dns.resolve4(originalHost);
      if (Array.isArray(addrs) && addrs.length > 0) {
        ipv4Host = addrs[0];
        console.log("✅ Resolved DB IPv4 via resolve4:", originalHost, "->", ipv4Host);
      } else {
        console.warn("⚠️ No A records via resolve4 for", originalHost);
      }
    } catch (err) {
      console.warn("⚠️ dns.resolve4 failed:", err && err.message ? err.message : err);
    }

    // 2) Fallback: dns.lookup family:4 (uses system resolver)
    if (!ipv4Host) {
      try {
        const lk = await dns.lookup(originalHost, { family: 4 });
        if (lk && lk.address) {
          ipv4Host = lk.address;
          console.log("✅ Resolved DB IPv4 via lookup:", originalHost, "->", ipv4Host);
        }
      } catch (err) {
        console.warn("⚠️ dns.lookup family:4 failed:", err && err.message ? err.message : err);
      }
    }

    // 3) Fallback: DoH via Google (dns.google)
    if (!ipv4Host) {
      try {
        const dohUrl = `https://dns.google/resolve?name=${encodeURIComponent(originalHost)}&type=A`;
        const dohResp = await axios.get(dohUrl, { timeout: 5000 });
        const answers = dohResp?.data?.Answer || dohResp?.data?.answer || [];
        if (Array.isArray(answers) && answers.length > 0) {
          for (const a of answers) {
            const ip = a.data || a;
            if (typeof ip === "string" && ip.match(/^\d{1,3}(\.\d{1,3}){3}$/)) {
              ipv4Host = ip;
              console.log("✅ Resolved DB IPv4 via DoH (dns.google):", originalHost, "->", ipv4Host);
              break;
            }
          }
        } else {
          console.warn("⚠️ DoH returned no A answers for", originalHost);
        }
      } catch (err) {
        console.warn("⚠️ DoH query failed:", err && err.message ? err.message : err);
      }
    }

    // Final host selection: prefer IPv4 if found, else use original hostname (may be IPv6-only)
    const hostToUse = ipv4Host || originalHost;

    // Build pool options preferring IPv4 IP if found
    const poolOptions = {
      user: parsed.username || undefined,
      password: parsed.password || undefined,
      host: hostToUse,
      port: parsed.port || 5432,
      database: parsed.pathname ? parsed.pathname.slice(1) : undefined,
      ssl: parsed.searchParams.get("sslmode") === "require" ? { rejectUnauthorized: false } : undefined,
    };

    const { Pool } = require("pg");
    pool = new Pool(poolOptions);

    // quick test to fail early if DB still unreachable
    await pool.query("SELECT 1");
    console.log("✅ Postgres pool created and reachable (host used):", poolOptions.host);
  } catch (err) {
    console.error("❌ Failed to create Postgres pool:", err && err.message ? err.message : err);
    // Do not exit process here so the app can start and surface errors in routes; uncomment next line to fail fast:
    // process.exit(1);
  }
})();

// ---------- Plan config ----------
const PLAN_CONFIG = {
  basic: {
    name: "Basic",
    dailyQuota: 50,
    features: { fullRag: false, summary: false },
  },
  pro: {
    name: "Pro",
    dailyQuota: 500,
    features: { fullRag: true, summary: false },
  },
  advanced: {
    name: "Advanced",
    dailyQuota: 2000,
    features: { fullRag: true, summary: true },
  },
};

// Demo site presets (auto-created when first used)
const DEMO_SITES = {
  "demo-basic": { name: "Demo - Basic Website Bot", plan: "basic", daily_quota: 10, status: "demo" },
  "demo-pro": { name: "Demo - Pro Website Bot", plan: "pro", daily_quota: 10, status: "demo" },
  "demo-advanced": { name: "Demo - Advanced Website Bot", plan: "advanced", daily_quota: 10, status: "demo" },
};

// ---------- Helpers ----------
function todayISODate() {
  return new Date().toISOString().slice(0, 10); // 'YYYY-MM-DD'
}

async function getSiteByDomain(domain) {
  const result = await db.query("SELECT * FROM sites WHERE domain = $1", [domain]);
  return result.rows[0];
}

async function getOrCreateDemoSite(siteDomain) {
  const demoConfig = DEMO_SITES[siteDomain];
  if (!demoConfig) return null;
  let existing = await getSiteByDomain(siteDomain);
  if (existing) return existing;
  const planConf = PLAN_CONFIG[demoConfig.plan] || PLAN_CONFIG.basic;
  const result = await db.query(
    `INSERT INTO sites (name, domain, plan, daily_quota, status) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [demoConfig.name, siteDomain, demoConfig.plan, demoConfig.daily_quota || planConf.dailyQuota, demoConfig.status || "demo"]
  );
  return result.rows[0];
}

async function getOrCreateConversation(siteId, sessionId) {
  let result = await db.query("SELECT * FROM conversations WHERE site_id = $1 AND session_id = $2", [siteId, sessionId]);
  if (result.rows[0]) return result.rows[0];
  const insert = await db.query("INSERT INTO conversations (site_id, session_id) VALUES ($1, $2) RETURNING *", [siteId, sessionId]);
  return insert.rows[0];
}

async function getOrCreateUsage(siteId, dateStr) {
  let result = await db.query("SELECT * FROM usage_daily WHERE site_id = $1 AND date = $2", [siteId, dateStr]);
  if (result.rows[0]) return result.rows[0];
  const insert = await db.query("INSERT INTO usage_daily (site_id, date, count) VALUES ($1, $2, 0) RETURNING *", [siteId, dateStr]);
  return insert.rows[0];
}

async function incrementUsage(siteId, dateStr) {
  await db.query("UPDATE usage_daily SET count = count + 1 WHERE site_id = $1 AND date = $2", [siteId, dateStr]);
  const r = await db.query("SELECT count FROM usage_daily WHERE site_id = $1 AND date = $2", [siteId, dateStr]);
  return r.rows[0]?.count || 0;
}

// Simple RAG using knowledge_items (for Pro/Advanced)
async function getRagContextForSite(siteId, userText, limit = 5) {
  const text = (userText || "").slice(0, 200);
  if (!text) return "";
  const like = `%${text}%`;
  const result = await db.query(
    `SELECT title, content FROM knowledge_items WHERE site_id = $1 AND (title ILIKE $2 OR content ILIKE $2) ORDER BY created_at DESC LIMIT $3`,
    [siteId, like, limit]
  );
  if (!result.rows.length) return "";
  return result.rows.map((row, idx) => `### ITEM ${idx + 1}: ${row.title}\n${row.content}`).join("\n\n");
}

// Call OpenAI Chat API via axios
async function callOpenAIChat(messages, { temperature = 0.6, max_tokens = 500 } = {}) {
  if (!OPENAI_API_KEY) {
    const e = new Error("OPENAI_API_KEY not set");
    e.code = "no_openai_key";
    throw e;
  }
  const resp = await axios.post(
    "https://api.openai.com/v1/chat/completions",
    { model: "gpt-4o-mini", messages, temperature, max_tokens },
    { timeout: 20000, headers: { "Content-Type": "application/json", Authorization: `Bearer ${OPENAI_API_KEY}` } }
  );
  const reply = resp?.data?.choices?.[0]?.message?.content?.trim() || resp?.data?.choices?.[0]?.text || "";
  return reply;
}

// Conversation summarization for Advanced plan (non-blocking)
async function summarizeConversation(conversationId) {
  try {
    const result = await db.query("SELECT role, text FROM messages WHERE conversation_id = $1 ORDER BY created_at ASC LIMIT 30", [conversationId]);
    if (!result.rows.length) return;
    const transcript = result.rows.map((m) => `${m.role.toUpperCase()}: ${m.text}`).join("\n");
    const prompt = `Summarize the following conversation between a website visitor and an assistant.\nUse 2–4 bullet points including the visitor's main question and important details.\n\nCONVERSATION:\n${transcript}`;
    const messages = [{ role: "system", content: "You summarize conversations for CRM usage." }, { role: "user", content: prompt }];
    const summary = await callOpenAIChat(messages, { temperature: 0.3, max_tokens: 200 });
    await db.query("UPDATE conversations SET summary = $1, last_summary_at = NOW() WHERE id = $2", [summary, conversationId]);
  } catch (err) {
    console.error("Summary error (non-blocking):", err && err.message ? err.message : err);
  }
}

// ---------- Middlewares ----------
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(express.json({ limit: "1mb" }));

// CORS - replace '*' with allowlist in production
app.use(cors({ origin: "*", methods: ["GET", "POST", "OPTIONS"], allowedHeaders: ["Content-Type", "Authorization"] }));

// Logging
morgan.token("reqid", () => Math.random().toString(36).slice(2, 9));
app.use(morgan(":reqid :method :url :status - :response-time ms", { skip: (r) => r.path === "/health" }));

// Rate limit AI & upload endpoints
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "10000", 10),
  max: parseInt(process.env.RATE_LIMIT_MAX || "8", 10),
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/chat", limiter);
app.use("/mascot/upload", limiter);

// ---------- Health ----------
app.get("/", (_req, res) => res.status(200).send("OK"));
app.get("/health", (_req, res) => res.json({ ok: true, service: "mascot-backend", time: new Date().toISOString() }));

app.get("/health-db", async (_req, res) => {
  try {
    const r = await db.query("SELECT NOW()");
    res.json({ ok: true, time: r.rows[0].now });
  } catch (err) {
    console.error("DB health error:", err && err.message ? err.message : err);
    res.status(500).json({ ok: false, error: err && err.message ? err.message : String(err) });
  }
});

// ---------- Diagnostics ----------
app.get("/openai/ping", async (_req, res) => {
  try {
    if (!OPENAI_API_KEY) return res.status(500).json({ ok: false, detail: "OPENAI_API_KEY not set" });
    const r = await axios.get("https://api.openai.com/v1/models", { headers: { Authorization: `Bearer ${OPENAI_API_KEY}` }, timeout: 10000 });
    res.json({ ok: true, count: r.data?.data?.length || 0 });
  } catch (e) {
    const status = e?.response?.status || 500;
    const detail = e?.response?.data || e.message;
    res.status(status).json({ ok: false, detail });
  }
});

// Helpful message if someone GETs /chat in a browser
app.get("/chat", (_req, res) => res.status(405).json({ error: "Use POST /chat", example: { message: "Hello" } }));

// ---------- Chat (OpenAI + RAG + per-site quota) ----------
app.post("/chat", async (req, res) => {
  try {
    const userMessage = (req.body?.message || req.body?.text || "").toString().trim();
    if (!userMessage) return res.status(400).json({ error: "missing_text", message: "Missing 'message' or 'text' in body." });

    if (!OPENAI_API_KEY) return res.status(500).json({ reply: "⚠️ Server not configured with OPENAI_API_KEY." });

    const pageUrl = (req.body?.pageUrl || "").toString();
    const siteRaw = (req.body?.site || "").toString().trim();
    const contextRaw = (req.body?.context || "").toString();
    const sessionIdRaw = (req.body?.sessionId || "").toString().trim();
    const originHeader = req.headers.origin || "";

    let siteDomain = siteRaw;
    if (!siteDomain && originHeader) {
      try { siteDomain = new URL(originHeader).hostname; } catch {}
    }
    if (!siteDomain) return res.status(400).json({ error: "unknown_site", message: "Site (domain) not provided. Please send 'site' in body or ensure Origin header is set." });

    let site = await getSiteByDomain(siteDomain);
    if (!site) site = await getOrCreateDemoSite(siteDomain);
    if (!site) return res.status(403).json({ error: "unknown_site", message: "This site is not registered with the chatbot service." });

    const planConf = PLAN_CONFIG[site.plan] || PLAN_CONFIG.basic;
    const today = todayISODate();

    const usage = await getOrCreateUsage(site.id, today);
    const effectiveQuota = site.daily_quota || planConf.dailyQuota;
    if (usage.count >= effectiveQuota) {
      return res.status(429).json({
        error: "daily_limit_reached",
        message: site.status === "demo" ? "Demo chat limit has been reached for today. Contact us to get full access." : "Daily chat limit has been reached for this site.",
        remaining: 0,
        reply: "Daily chat limit has been reached for this site. Please try again tomorrow."
      });
    }

    const sessionId = sessionIdRaw || `anon-${Date.now()}`;
    const conversation = await getOrCreateConversation(site.id, sessionId);

    try {
      await db.query("INSERT INTO messages (conversation_id, role, text, page_url) VALUES ($1, $2, $3, $4)", [conversation.id, "user", userMessage, pageUrl || null]);
    } catch (e) {
      console.warn("Failed to log user message:", e && e.message ? e.message : e);
    }

    const contextText = contextRaw.trim().slice(0, 3000) || "No specific page context was provided.";
    let extraRagContext = "";
    if (planConf.features.fullRag) {
      try { extraRagContext = await getRagContextForSite(site.id, userMessage); } catch (e) { console.warn("RAG context retrieval failed:", e && e.message ? e.message : e); extraRagContext = ""; }
    }

    const baseSystemPrompt = site.plan === "advanced" ? "You are an advanced website assistant. Use website content and knowledge base. Act like a smart sales + support agent, but stay concise and clear." : site.plan === "pro" ? "You are a website assistant with access to a knowledge base. Use it to answer accurately and clearly." : "You are a simple helpful assistant for this website. Be concise and friendly.";
    const systemContext = "You are embedded on a website as a chat widget. Use the provided CONTEXT from the current page when it is relevant. If the context is not helpful, fall back to general knowledge but keep it relevant to this business.";
    const contextPrompt = ["CONTEXT FROM WEBSITE / APP:", `Site: ${siteDomain}`, `Page URL: ${pageUrl || "unknown"}`, "---", contextText, extraRagContext ? "\nADDITIONAL SITE KNOWLEDGE:\n" + extraRagContext : ""].join("\n");

    const messages = [
      { role: "system", content: baseSystemPrompt },
      { role: "system", content: systemContext },
      { role: "system", content: contextPrompt },
      { role: "user", content: userMessage },
    ];

    let reply;
    try {
      reply = await callOpenAIChat(messages, { temperature: 0.6, max_tokens: 500 });
    } catch (err) {
      const status = err?.response?.status || 502;
      const code = err?.response?.data?.error?.code;
      const friendly = code === "insufficient_quota" ? "⚠️ Demo usage limit reached. Please try again later." : "⚠️ I’m having trouble reaching the AI service. Please try again.";
      console.error("OpenAI /chat error:", err?.response?.data || err.message || err);
      return res.status(status).json({ reply: friendly });
    }

    try {
      await db.query("INSERT INTO messages (conversation_id, role, text, page_url) VALUES ($1, $2, $3, $4)", [conversation.id, "assistant", reply, pageUrl || null]);
    } catch (e) {
      console.warn("Failed to log assistant message:", e && e.message ? e.message : e);
    }

    try {
      await db.query("UPDATE usage_daily SET count = count + 1 WHERE site_id = $1 AND date = $2", [site.id, today]);
    } catch (e) {
      console.warn("Failed to increment usage_daily:", e && e.message ? e.message : e);
    }
    let newCount = usage.count + 1;
    try {
      const newUsage = await db.query("SELECT count FROM usage_daily WHERE site_id = $1 AND date = $2", [site.id, today]);
      newCount = newUsage.rows[0]?.count ?? newCount;
    } catch (e) {}

    const effectiveQuotaLocal = site.daily_quota || planConf.dailyQuota;
    const remaining = Math.max(effectiveQuotaLocal - newCount, 0);

    if (planConf.features.summary) setImmediate(() => summarizeConversation(conversation.id));

    return res.json({ reply, remaining, plan: site.plan, status: site.status });
  } catch (err) {
    console.error("Unhandled /chat error:", err && err.message ? err.message : err);
    return res.status(500).json({ reply: "⚠️ Server error. Please try again later." });
  }
});

// ---------- Mascot Upload (local storage) ----------
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } }); // 5MB
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
app.use("/uploads", express.static(UPLOAD_DIR));

app.post("/mascot/upload", upload.single("mascot"), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: "No file uploaded. Field name 'mascot'." });
    const safeName = `${Date.now()}_${(req.file.originalname || "mascot").replace(/[^\w.-]/g, "_")}`;
    fs.writeFileSync(path.join(UPLOAD_DIR, safeName), req.file.buffer);
    return res.json({ success: true, url: `/uploads/${safeName}` });
  } catch (e) {
    console.error("Upload error:", e && e.message ? e.message : e);
    return res.status(500).json({ success: false, error: "Upload failed." });
  }
});

// ---------- Start ----------
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT} (mascot-backend). OpenAI key ${OPENAI_API_KEY ? "present" : "MISSING"}`));
