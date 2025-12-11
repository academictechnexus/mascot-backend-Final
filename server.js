// server.js
// Full-featured mascot chatbot backend
// - preserves all original routes & features (multi-tenant, plans, RAG, summarization, uploads, diagnostics)
// - robust DB init: PGHOST_IPV4 env override -> resolve4 -> lookup(family:4) -> DoH -> hostname
// - Neon SNI fix: ensure ssl.servername set to original hostname so TLS cert matches when using IPv4
// Keep env vars: DATABASE_URL, OPENAI_API_KEY. Optionally set PGHOST_IPV4 to force IPv4.

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
// trust proxy so express-rate-limit sees X-Forwarded-For correctly behind Railway / Cloudflare
app.set("trust proxy", true);

const PORT = process.env.PORT || 8080;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const RAW_DATABASE_URL = process.env.DATABASE_URL || ""; // note: raw env
// Optional override: set this in Railway env to force IPv4 host
const PGHOST_IPV4 = process.env.PGHOST_IPV4 || "";

if (!RAW_DATABASE_URL) {
  console.warn("⚠️ DATABASE_URL not set — server will proceed but DB calls will fail.");
}

// ---------- DB init (Neon-aware, robust IPv4 resolution with PGHOST_IPV4 override) ----------
let pool = null;
const db = {
  query: (text, params) => {
    if (!pool) throw new Error("Postgres pool not initialized yet");
    return pool.query(text, params);
  },
};

/**
 * Ensure Neon connection string contains options=endpoint=<endpoint-id> and sslmode=require.
 * If ipv4Host is provided (an IP), we replace hostname with the IP but KEEP the endpoint option derived from original host.
 *
 * Returns: finalConnectionString (string) or null if invalid input.
 */
function buildNeonConnectionString(raw, ipv4HostFallback) {
  if (!raw) return null;
  // Trim and remove surrounding quotes or stray single-quotes
  let u = raw.trim().replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1");

  let parsed;
  try {
    parsed = new URL(u);
  } catch (e) {
    console.error("❌ buildNeonConnectionString: invalid DATABASE_URL format:", e.message);
    return null;
  }

  // Extract original hostname and endpoint id (for Neon pooler hostnames)
  const originalHost = parsed.hostname; // e.g. ep-polished-sky-a12jufhs-pooler.ap-...
  const firstLabel = originalHost.split(".")[0] || "";
  // endpoint id is firstLabel without trailing "-pooler" (if present)
  const endpointId = firstLabel.replace(/-pooler$/i, "");

  // Ensure sslmode=require if not already present
  const params = parsed.searchParams;
  if (!params.has("sslmode")) params.set("sslmode", "require");

  // Ensure options param set to endpoint=<endpoint-id>
  if (endpointId) {
    // set will URL-encode value when we reserialize
    params.set("options", `endpoint=${endpointId}`);
  }

  // If caller provided an IPv4 host, override hostname with it (keep port & auth & db path)
  if (ipv4HostFallback && ipv4HostFallback.match(/^\d{1,3}(\.\d{1,3}){3}$/)) {
    parsed.hostname = ipv4HostFallback;
    // Note: URL will preserve port and credentials
  }

  // Reassign search params (ensures encoding)
  parsed.search = params.toString();
  return parsed.toString();
}

(async function initPostgresPool() {
  try {
    if (!RAW_DATABASE_URL) {
      console.warn("⚠️ DATABASE_URL not set — pool cannot be created.");
      return;
    }

    // Parse the raw URL to identify original host (for endpoint extraction)
    const parsedRaw = (() => {
      try { return new URL(RAW_DATABASE_URL.trim().replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1")); }
      catch (e) { console.error("❌ Invalid RAW DATABASE_URL:", e.message); return null; }
    })();

    if (!parsedRaw) {
      console.error("❌ Aborting DB init: invalid RAW DATABASE_URL.");
      return;
    }

    const originalHost = parsedRaw.hostname;
    let resolvedIPv4 = null;

    // 0) Highest priority: PGHOST_IPV4 override (explicit IP string)
    if (PGHOST_IPV4 && PGHOST_IPV4.match(/^\d{1,3}(\.\d{1,3}){3}$/)) {
      resolvedIPv4 = PGHOST_IPV4;
      console.log("✅ Using PGHOST_IPV4 override:", resolvedIPv4);
    }

    // 1) Try dns.resolve4 (direct A-record query)
    if (!resolvedIPv4) {
      try {
        const addrs = await dns.resolve4(originalHost);
        if (Array.isArray(addrs) && addrs.length > 0) {
          resolvedIPv4 = addrs[0];
          console.log("✅ Resolved DB IPv4 via resolve4:", originalHost, "->", resolvedIPv4);
        } else {
          console.warn("⚠️ No A records via resolve4 for", originalHost);
        }
      } catch (err) {
        console.warn("⚠️ dns.resolve4 failed:", err && err.message ? err.message : err);
      }
    }

    // 2) Fallback: dns.lookup family:4 (uses system resolver)
    if (!resolvedIPv4) {
      try {
        const lk = await dns.lookup(originalHost, { family: 4 });
        if (lk && lk.address) {
          resolvedIPv4 = lk.address;
          console.log("✅ Resolved DB IPv4 via lookup:", originalHost, "->", resolvedIPv4);
        }
      } catch (err) {
        console.warn("⚠️ dns.lookup family:4 failed:", err && err.message ? err.message : err);
      }
    }

    // 3) Fallback: DoH via Google (dns.google)
    if (!resolvedIPv4) {
      try {
        const dohUrl = `https://dns.google/resolve?name=${encodeURIComponent(originalHost)}&type=A`;
        const dohResp = await axios.get(dohUrl, { timeout: 5000 });
        const answers = dohResp?.data?.Answer || dohResp?.data?.answer || [];
        if (Array.isArray(answers) && answers.length > 0) {
          for (const a of answers) {
            const ip = a.data || a;
            if (typeof ip === "string" && ip.match(/^\d{1,3}(\.\d{1,3}){3}$/)) {
              resolvedIPv4 = ip;
              console.log("✅ Resolved DB IPv4 via DoH (dns.google):", originalHost, "->", resolvedIPv4);
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

    // Build final connection string:
    // If we have a resolved IPv4, pass it to builder so it uses IP but still includes `options=endpoint=...`
    const finalConnString = buildNeonConnectionString(RAW_DATABASE_URL, resolvedIPv4);

    // For debug: log raw env and final conn string (password redacted)
    console.log("🔍 RAW process.env.DATABASE_URL:", JSON.stringify(RAW_DATABASE_URL));
    console.log("🔧 Final DATABASE_URL used (password redacted):", finalConnString ? finalConnString.replace(/:\/\/([^:]+):([^@]+)@/, "://$1:REDACTED@") : null);

    if (!finalConnString) {
      console.error("❌ Final connection string could not be constructed. Pool will not be created.");
      return;
    }

    // --- Create pg Pool using connectionString (Neon + IPv4 + SNI fix) ---
    const { Pool } = require("pg");

    // build sslOptions and set servername for SNI so cert alt names match
    const sslOptions = { rejectUnauthorized: false };
    try {
      if (parsedRaw && parsedRaw.hostname) {
        sslOptions.servername = parsedRaw.hostname; // important: set to Neon hostname for SNI
      }
    } catch (e) {
      // no-op
    }

    pool = new Pool({
      connectionString: finalConnString,       // contains options=endpoint=... and may contain IP host
      ssl: sslOptions,                         // ensure servername set to originalHost for SNI
      allowExitOnIdle: true,
    });

    // quick test to fail early if DB still unreachable
    try {
      await pool.query("SELECT 1");
      console.log("✅ Postgres pool created and reachable (final host used):", resolvedIPv4 || originalHost);
    } catch (err) {
      console.error("❌ Postgres test query failed after creating pool:", err && err.message ? err.message : err);
    }
  } catch (err) {
    console.error("❌ Failed to create Postgres pool:", err && err.message ? err.message : err);
    // Keep the process running so rest of service is available for debugging.
    // If you prefer fail-fast (so deployment fails), uncomment next line:
    // process.exit(1);
  }
})();

// ---------- Plan config ----------
const PLAN_CONFIG = {
  basic: { name: "Basic", dailyQuota: 50, features: { fullRag: false, summary: false } },
  pro: { name: "Pro", dailyQuota: 500, features: { fullRag: true, summary: false } },
  advanced: { name: "Advanced", dailyQuota: 2000, features: { fullRag: true, summary: true } },
};

// Demo site presets (auto-created when first used)
const DEMO_SITES = {
  "demo-basic": { name: "Demo - Basic Website Bot", plan: "basic", daily_quota: 10, status: "demo" },
  "demo-pro": { name: "Demo - Pro Website Bot", plan: "pro", daily_quota: 10, status: "demo" },
  "demo-advanced": { name: "Demo - Advanced Website Bot", plan: "advanced", daily_quota: 10, status: "demo" },
};

// ---------- Helpers ----------
function todayISODate() { return new Date().toISOString().slice(0, 10); }

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

// Simple RAG
async function getRagContextForSite(siteId, userText, limit = 5) {
  const text = (userText || "").slice(0, 200);
  if (!text) return "";
  const like = `%${text}%`;
  const result = await db.query("SELECT title, content FROM knowledge_items WHERE site_id = $1 AND (title ILIKE $2 OR content ILIKE $2) ORDER BY created_at DESC LIMIT $3", [siteId, like, limit]);
  if (!result.rows.length) return "";
  return result.rows.map((row, idx) => `### ITEM ${idx+1}: ${row.title}\n${row.content}`).join("\n\n");
}

// OpenAI Chat call
async function callOpenAIChat(messages, { temperature = 0.6, max_tokens = 500 } = {}) {
  if (!OPENAI_API_KEY) {
    const e = new Error("OPENAI_API_KEY not set");
    e.code = "no_openai_key";
    throw e;
  }
  const resp = await axios.post("https://api.openai.com/v1/chat/completions", { model: "gpt-4o-mini", messages, temperature, max_tokens }, { timeout: 20000, headers: { "Content-Type": "application/json", Authorization: `Bearer ${OPENAI_API_KEY}` } });
  const reply = resp?.data?.choices?.[0]?.message?.content?.trim() || resp?.data?.choices?.[0]?.text || "";
  return reply;
}

// Conversation summarization
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
app.use(cors({ origin: "*", methods: ["GET","POST","OPTIONS"], allowedHeaders: ["Content-Type","Authorization"] }));

morgan.token("reqid", () => Math.random().toString(36).slice(2, 9));
app.use(morgan(":reqid :method :url :status - :response-time ms", { skip: (r) => r.path === "/health" }));

const limiter = rateLimit({ windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "10000", 10), max: parseInt(process.env.RATE_LIMIT_MAX || "8", 10), standardHeaders: true, legacyHeaders: false });
app.use("/chat", limiter);
app.use("/mascot/upload", limiter);

// ---------- Health ----------
app.get("/", (_req, res) => res.status(200).send("OK"));
app.get("/health", (_req, res) => res.json({ ok: true, service: "mascot-backend", time: new Date().toISOString() }));
app.get("/health-db", async (_req, res) => {
  try { const r = await db.query("SELECT NOW()"); res.json({ ok: true, time: r.rows[0].now }); } catch (err) { console.error("DB health error:", err && err.message ? err.message : err); res.status(500).json({ ok: false, error: err && err.message ? err.message : String(err) }); }
});

// ---------- Diagnostics ----------
app.get("/openai/ping", async (_req, res) => {
  try { if (!OPENAI_API_KEY) return res.status(500).json({ ok: false, detail: "OPENAI_API_KEY not set" }); const r = await axios.get("https://api.openai.com/v1/models", { headers: { Authorization: `Bearer ${OPENAI_API_KEY}` }, timeout: 10000 }); res.json({ ok: true, count: r.data?.data?.length || 0 }); } catch (e) { const status = e?.response?.status || 500; const detail = e?.response?.data || e.message; res.status(status).json({ ok: false, detail }); }
});

// GET /chat helpful
app.get("/chat", (_req, res) => res.status(405).json({ error: "Use POST /chat", example: { message: "Hello" } }));

// ---------- Chat endpoint ----------
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
    if (!siteDomain && originHeader) { try { siteDomain = new URL(originHeader).hostname; } catch {} }
    if (!siteDomain) return res.status(400).json({ error: "unknown_site", message: "Site (domain) not provided. Please send 'site' in body or ensure Origin header is set." });

    let site = await getSiteByDomain(siteDomain);
    if (!site) site = await getOrCreateDemoSite(siteDomain);
    if (!site) return res.status(403).json({ error: "unknown_site", message: "This site is not registered with the chatbot service." });

    const planConf = PLAN_CONFIG[site.plan] || PLAN_CONFIG.basic;
    const today = todayISODate();

    const usage = await getOrCreateUsage(site.id, today);
    const effectiveQuota = site.daily_quota || planConf.dailyQuota;
    if (usage.count >= effectiveQuota) return res.status(429).json({ error: "daily_limit_reached", message: site.status === "demo" ? "Demo chat limit has been reached for today. Contact us to get full access." : "Daily chat limit has been reached for this site.", remaining: 0, reply: "Daily chat limit has been reached for this site. Please try again tomorrow." });

    const sessionId = sessionIdRaw || `anon-${Date.now()}`;
    const conversation = await getOrCreateConversation(site.id, sessionId);

    try { await db.query("INSERT INTO messages (conversation_id, role, text, page_url) VALUES ($1,$2,$3,$4)", [conversation.id, "user", userMessage, pageUrl || null]); } catch (e) { console.warn("Failed to log user message:", e && e.message ? e.message : e); }

    const contextText = contextRaw.trim().slice(0, 3000) || "No specific page context was provided.";
    let extraRagContext = "";
    if (planConf.features.fullRag) { try { extraRagContext = await getRagContextForSite(site.id, userMessage); } catch (e) { console.warn("RAG context retrieval failed:", e && e.message ? e.message : e); extraRagContext = ""; } }

    const baseSystemPrompt = site.plan === "advanced" ? "You are an advanced website assistant. Use website content and knowledge base. Act like a smart sales + support agent, but stay concise and clear." : site.plan === "pro" ? "You are a website assistant with access to a knowledge base. Use it to answer accurately and clearly." : "You are a simple helpful assistant for this website. Be concise and friendly.";
    const systemContext = "You are embedded on a website as a chat widget. Use the provided CONTEXT from the current page when it is relevant. If the context is not helpful, fall back to general knowledge but keep it relevant to this business.";
    const contextPrompt = ["CONTEXT FROM WEBSITE / APP:", `Site: ${siteDomain}`, `Page URL: ${pageUrl || "unknown"}`, "---", contextText, extraRagContext ? "\nADDITIONAL SITE KNOWLEDGE:\n" + extraRagContext : ""].join("\n");

    const messages = [{ role: "system", content: baseSystemPrompt }, { role: "system", content: systemContext }, { role: "system", content: contextPrompt }, { role: "user", content: userMessage }];

    let reply;
    try { reply = await callOpenAIChat(messages, { temperature: 0.6, max_tokens: 500 }); } catch (err) { const status = err?.response?.status || 502; const code = err?.response?.data?.error?.code; const friendly = code === "insufficient_quota" ? "⚠️ Demo usage limit reached. Please try again later." : "⚠️ I’m having trouble reaching the AI service. Please try again."; console.error("OpenAI /chat error:", err?.response?.data || err.message || err); return res.status(status).json({ reply: friendly }); }

    try { await db.query("INSERT INTO messages (conversation_id, role, text, page_url) VALUES ($1,$2,$3,$4)", [conversation.id, "assistant", reply, pageUrl || null]); } catch (e) { console.warn("Failed to log assistant message:", e && e.message ? e.message : e); }

    try { await db.query("UPDATE usage_daily SET count = count + 1 WHERE site_id = $1 AND date = $2", [site.id, today]); } catch (e) { console.warn("Failed to increment usage_daily:", e && e.message ? e.message : e); }
    let newCount = usage.count + 1;
    try { const newUsage = await db.query("SELECT count FROM usage_daily WHERE site_id = $1 AND date = $2", [site.id, today]); newCount = newUsage.rows[0]?.count ?? newCount; } catch (e) {}
    const remaining = Math.max((site.daily_quota || planConf.dailyQuota) - newCount, 0);

    if (planConf.features.summary) setImmediate(() => summarizeConversation(conversation.id));
    return res.json({ reply, remaining, plan: site.plan, status: site.status });
  } catch (err) {
    console.error("Unhandled /chat error:", err && err.message ? err.message : err);
    return res.status(500).json({ reply: "⚠️ Server error. Please try again later." });
  }
});

// ---------- Upload ----------
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });
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
