// server.js
// Product-ready backend: multi-tenant, plans, quotas, RAG, summaries, demo auto-create.

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const axios = require("axios");
const morgan = require("morgan");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

// ---------- Config ----------
const PORT = process.env.PORT || 8080;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error("❌ Missing DATABASE_URL env var");
  process.exit(1);
}
if (!OPENAI_API_KEY) {
  console.error("⚠️ Warning: OPENAI_API_KEY not set. /chat will not work.");
}

// ---------- DB ----------
const pool = new Pool({
  connectionString: DATABASE_URL,
  // If you get SSL errors locally, uncomment:
  // ssl: { rejectUnauthorized: false },
});

const db = {
  query: (text, params) => pool.query(text, params),
};

// ---------- Plan config ----------
const PLAN_CONFIG = {
  basic: {
    name: "Basic",
    dailyQuota: 50,
    features: {
      fullRag: false,  // no knowledge_items
      summary: false,  // no conversation summary
    },
  },
  pro: {
    name: "Pro",
    dailyQuota: 500,
    features: {
      fullRag: true,   // use knowledge_items
      summary: false,
    },
  },
  advanced: {
    name: "Advanced",
    dailyQuota: 2000,
    features: {
      fullRag: true,
      summary: true,   // generate conversation summary
    },
  },
};

// Demo site presets (auto-created when first used)
const DEMO_SITES = {
  "demo-basic": {
    name: "Demo - Basic Website Bot",
    plan: "basic",
    daily_quota: 10,
    status: "demo",
  },
  "demo-pro": {
    name: "Demo - Pro Website Bot",
    plan: "pro",
    daily_quota: 10,
    status: "demo",
  },
  "demo-advanced": {
    name: "Demo - Advanced Website Bot",
    plan: "advanced",
    daily_quota: 10,
    status: "demo",
  },
};

// ---------- Helpers ----------
function todayISODate() {
  return new Date().toISOString().slice(0, 10); // 'YYYY-MM-DD'
}

async function getSiteByDomain(domain) {
  const result = await db.query("SELECT * FROM sites WHERE domain = $1", [domain]);
  return result.rows[0];
}

// Auto-create site only if it's one of the known demo IDs
async function getOrCreateDemoSite(siteDomain) {
  const demoConfig = DEMO_SITES[siteDomain];
  if (!demoConfig) return null; // not a demo code we know

  // check if it already exists
  let existing = await getSiteByDomain(siteDomain);
  if (existing) return existing;

  const planConf = PLAN_CONFIG[demoConfig.plan] || PLAN_CONFIG.basic;

  const result = await db.query(
    `
    INSERT INTO sites (name, domain, plan, daily_quota, status)
    VALUES ($1, $2, $3, $4, $5)
    RETURNING *
    `,
    [
      demoConfig.name,
      siteDomain,
      demoConfig.plan,
      demoConfig.daily_quota || planConf.dailyQuota,
      demoConfig.status || "demo",
    ]
  );
  return result.rows[0];
}

async function getOrCreateConversation(siteId, sessionId) {
  let result = await db.query(
    "SELECT * FROM conversations WHERE site_id = $1 AND session_id = $2",
    [siteId, sessionId]
  );
  if (result.rows[0]) return result.rows[0];

  const insert = await db.query(
    "INSERT INTO conversations (site_id, session_id) VALUES ($1, $2) RETURNING *",
    [siteId, sessionId]
  );
  return insert.rows[0];
}

async function getOrCreateUsage(siteId, dateStr) {
  let result = await db.query(
    "SELECT * FROM usage_daily WHERE site_id = $1 AND date = $2",
    [siteId, dateStr]
  );
  if (result.rows[0]) return result.rows[0];

  const insert = await db.query(
    "INSERT INTO usage_daily (site_id, date, count) VALUES ($1, $2, 0) RETURNING *",
    [siteId, dateStr]
  );
  return insert.rows[0];
}

// Simple RAG using knowledge_items (for Pro/Advanced)
async function getRagContextForSite(siteId, userText, limit = 5) {
  const text = userText.slice(0, 200); // crude but fine for V1
  const like = `%${text}%`;

  const result = await db.query(
    `
    SELECT title, content
    FROM knowledge_items
    WHERE site_id = $1
      AND (title ILIKE $2 OR content ILIKE $2)
    ORDER BY created_at DESC
    LIMIT $3
    `,
    [siteId, like, limit]
  );

  if (!result.rows.length) return "";

  const blocks = result.rows.map(
    (row, idx) => `### ITEM ${idx + 1}: ${row.title}\n${row.content}`
  );

  return blocks.join("\n\n");
}

// Call OpenAI Chat API via axios
async function callOpenAIChat(messages, { temperature = 0.6, max_tokens = 500 } = {}) {
  const resp = await axios.post(
    "https://api.openai.com/v1/chat/completions",
    {
      model: "gpt-4o-mini",
      messages,
      temperature,
      max_tokens,
    },
    {
      timeout: 20000,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${OPENAI_API_KEY}`,
      },
    }
  );

  const reply =
    resp?.data?.choices?.[0]?.message?.content?.trim() ||
    "Sorry, I couldn’t generate a response.";
  return reply;
}

// Conversation summarization for Advanced plan (non-blocking)
async function summarizeConversation(conversationId) {
  try {
    const result = await db.query(
      `
      SELECT role, text
      FROM messages
      WHERE conversation_id = $1
      ORDER BY created_at ASC
      LIMIT 30
      `,
      [conversationId]
    );

    if (!result.rows.length) return;

    const transcript = result.rows
      .map((m) => `${m.role.toUpperCase()}: ${m.text}`)
      .join("\n");

    const prompt = `
Summarize the following conversation between a website visitor and an assistant.
Use 2–4 bullet points including the visitor's main question and important details.

CONVERSATION:
${transcript}
`.trim();

    const messages = [
      { role: "system", content: "You summarize conversations for CRM usage." },
      { role: "user", content: prompt },
    ];

    const summary = await callOpenAIChat(messages, {
      temperature: 0.3,
      max_tokens: 200,
    });

    await db.query(
      "UPDATE conversations SET summary = $1, last_summary_at = NOW() WHERE id = $2",
      [summary, conversationId]
    );
  } catch (err) {
    console.error("Summary error (non-blocking):", err.message);
  }
}

// ---------- Middlewares ----------
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);
app.use(express.json({ limit: "1mb" }));

// CORS for all routes
const corsOptions = {
  origin: "*",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};
app.use(cors(corsOptions));

// **IMPORTANT**: handle preflight OPTIONS so browser doesn't fail with "Network error"
app.options("*", cors(corsOptions));

// Logging (no bodies)
morgan.token("reqid", () => Math.random().toString(36).slice(2, 9));
app.use(
  morgan(":reqid :method :url :status - :response-time ms", {
    skip: (r) => r.path === "/health",
  })
);

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
app.get("/health", (_req, res) =>
  res.json({
    ok: true,
    service: "mascot-backend",
    time: new Date().toISOString(),
  })
);

// Optional DB health check (useful for debugging)
app.get("/health-db", async (_req, res) => {
  try {
    const r = await db.query("SELECT NOW()");
    res.json({ ok: true, time: r.rows[0].now });
  } catch (err) {
    console.error("DB health error:", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ---------- Diagnostics ----------
app.get("/openai/ping", async (_req, res) => {
  try {
    if (!OPENAI_API_KEY)
      return res
        .status(500)
        .json({ ok: false, detail: "OPENAI_API_KEY not set" });
    const r = await axios.get("https://api.openai.com/v1/models", {
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}` },
      timeout: 10000,
    });
    res.json({ ok: true, count: r.data?.data?.length || 0 });
  } catch (e) {
    const status = e?.response?.status || 500;
    const detail = e?.response?.data || e.message;
    res.status(status).json({ ok: false, detail });
  }
});

// Helpful message if someone GETs /chat in a browser
app.get("/chat", (_req, res) =>
  res
    .status(405)
    .json({ error: "Use POST /chat", example: { message: "Hello" } })
);

// ---------- Chat (OpenAI + RAG + per-site quota) ----------

app.post("/chat", async (req, res) => {
  try {
    // support both old shape {message} and new {text}
    const userMessage = (req.body?.message || req.body?.text || "")
      .toString()
      .trim();

    if (!userMessage) {
      return res
        .status(400)
        .json({ error: "missing_text", message: "Missing 'message' or 'text' in body." });
    }

    if (!OPENAI_API_KEY) {
      return res.status(500).json({
        reply: "⚠️ Server not configured with OPENAI_API_KEY.",
      });
    }

    const pageUrl = (req.body?.pageUrl || "").toString();
    const siteRaw = (req.body?.site || "").toString().trim();
    const contextRaw = (req.body?.context || "").toString();
    const sessionIdRaw = (req.body?.sessionId || "").toString().trim();

    const originHeader = req.headers.origin || "";

    // Determine siteDomain (for DB)
    let siteDomain = siteRaw;
    if (!siteDomain && originHeader) {
      try {
        siteDomain = new URL(originHeader).hostname;
      } catch {
        // ignore URL parse errors
      }
    }

    if (!siteDomain) {
      return res.status(400).json({
        error: "unknown_site",
        message:
          "Site (domain) not provided. Please send 'site' in body or ensure Origin header is set.",
      });
    }

    // 1) Find site in DB or auto-create demo sites
    let site = await getSiteByDomain(siteDomain);
    if (!site) {
      // if it's a known demo ID, auto-create demo site
      site = await getOrCreateDemoSite(siteDomain);
    }
    if (!site) {
      return res.status(403).json({
        error: "unknown_site",
        message: "This site is not registered with the chatbot service.",
      });
    }

    const planConf = PLAN_CONFIG[site.plan] || PLAN_CONFIG.basic;
    const today = todayISODate();

    // 2) Quota check
    const usage = await getOrCreateUsage(site.id, today);
    const effectiveQuota = site.daily_quota || planConf.dailyQuota;

    if (usage.count >= effectiveQuota) {
      return res.status(429).json({
        error: "daily_limit_reached",
        message:
          site.status === "demo"
            ? "Demo chat limit has been reached for today. Contact us to get full access."
            : "Daily chat limit has been reached for this site.",
        remaining: 0,
        reply:
          "Daily chat limit has been reached for this site. Please try again tomorrow.",
      });
    }

    // 3) Conversation (session-based)
    const sessionId = sessionIdRaw || `anon-${Date.now()}`;
    const conversation = await getOrCreateConversation(site.id, sessionId);

    // 4) Log user message
    await db.query(
      "INSERT INTO messages (conversation_id, role, text, page_url) VALUES ($1, $2, $3, $4)",
      [conversation.id, "user", userMessage, pageUrl || null]
    );

    // 5) Build context (Basic vs Pro/Advanced)
    const contextText =
      contextRaw.trim().slice(0, 3000) ||
      "No specific page context was provided.";

    let extraRagContext = "";
    if (planConf.features.fullRag) {
      extraRagContext = await getRagContextForSite(site.id, userMessage);
    }

    const baseSystemPrompt =
      site.plan === "advanced"
        ? "You are an advanced website assistant. Use website content and knowledge base. Act like a smart sales + support agent, but stay concise and clear."
        : site.plan === "pro"
        ? "You are a website assistant with access to a knowledge base. Use it to answer accurately and clearly."
        : "You are a simple helpful assistant for this website. Be concise and friendly.";

    const systemContext = [
      "You are embedded on a website as a chat widget.",
      "Use the provided CONTEXT from the current page when it is relevant.",
      "If the context is not helpful, fall back to general knowledge but keep it relevant to this business.",
    ].join(" ");

    const contextPrompt = [
      "CONTEXT FROM WEBSITE / APP:",
      `Site: ${siteDomain}`,
      `Page URL: ${pageUrl || "unknown"}`,
      "---",
      contextText,
      extraRagContext ? "\nADDITIONAL SITE KNOWLEDGE:\n" + extraRagContext : "",
    ].join("\n");

    const messages = [
      { role: "system", content: baseSystemPrompt },
      { role: "system", content: systemContext },
      { role: "system", content: contextPrompt },
      { role: "user", content: userMessage },
    ];

    // 6) Call OpenAI
    let reply;
    try {
      reply = await callOpenAIChat(messages, {
        temperature: 0.6,
        max_tokens: 500,
      });
    } catch (err) {
      const status = err?.response?.status || 502;
      const code = err?.response?.data?.error?.code;
      const friendly =
        code === "insufficient_quota"
          ? "⚠️ Demo usage limit reached. Please try again later."
          : "⚠️ I’m having trouble reaching the AI service. Please try again.";
      console.error("OpenAI /chat error:", err?.response?.data || err.message);
      return res.status(status).json({ reply: friendly });
    }

    // 7) Log assistant reply
    await db.query(
      "INSERT INTO messages (conversation_id, role, text, page_url) VALUES ($1, $2, $3, $4)",
      [conversation.id, "assistant", reply, pageUrl || null]
    );

    // 8) Increment usage
    await db.query(
      "UPDATE usage_daily SET count = count + 1 WHERE site_id = $1 AND date = $2",
      [site.id, today]
    );
    const newUsage = await db.query(
      "SELECT count FROM usage_daily WHERE site_id = $1 AND date = $2",
      [site.id, today]
    );
    const newCount = newUsage.rows[0]?.count ?? usage.count + 1;
    const remaining = Math.max(effectiveQuota - newCount, 0);

    // 9) Advanced: summarize conversation (fire-and-forget)
    if (planConf.features.summary) {
      summarizeConversation(conversation.id);
    }

    return res.json({
      reply,
      remaining,
      plan: site.plan,
      status: site.status,
    });
  } catch (err) {
    console.error("Unhandled /chat error:", err);
    return res.status(500).json({ reply: "⚠️ Server error. Please try again later." });
  }
});

// ---------- Mascot Upload (local storage) ----------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
}); // 5MB
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
app.use("/uploads", express.static(UPLOAD_DIR));

app.post("/mascot/upload", upload.single("mascot"), (req, res) => {
  try {
    if (!req.file)
      return res
        .status(400)
        .json({ success: false, error: "No file uploaded. Field name 'mascot'." });
    const safeName = `${Date.now()}_${(
      req.file.originalname || "mascot"
    ).replace(/[^\w.-]/g, "_")}`;
    fs.writeFileSync(path.join(UPLOAD_DIR, safeName), req.file.buffer);
    return res.json({ success: true, url: `/uploads/${safeName}` });
  } catch (e) {
    console.error("Upload error:", e.message);
    return res.status(500).json({ success: false, error: "Upload failed." });
  }
});

// ---------- Start ----------
app.listen(PORT, () =>
  console.log(`✅ Server running on port ${PORT}`)
);
