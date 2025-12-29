// server.js
// Mascot backend — FINAL integrated version
// Zendesk-style backend for SMBs (SAFE, NON-BREAKING)

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
const crypto = require("crypto");
const { URL } = require("url");
require("dotenv").config();

/* ===========================
   NEW: workflows & routes
=========================== */
const chatWorkflow = require("./workflows/chat.workflow");
const onboardingRoutes = require("./routes/onboarding.routes");
const channelRoutes = require("./routes/channel.routes");
const reportsRoutes = require("./routes/reports.routes");

/* ===========================
   Optional libs
=========================== */
let nodemailer = null;
try { nodemailer = require("nodemailer"); } catch (e) {}

let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  try { stripe = require("stripe")(process.env.STRIPE_SECRET_KEY); }
  catch (e) { stripe = null; }
}

const app = express();
app.set("trust proxy", true);

const PORT = process.env.PORT || 8080;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const RAW_DATABASE_URL = process.env.DATABASE_URL || "";
const DEMO_DAYS = parseInt(process.env.DEMO_DAYS || "7", 10);
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || null;

/* ===========================
   Email config
=========================== */
const SMTP_ENABLED = !!(
  process.env.SMTP_HOST &&
  process.env.SMTP_PORT &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS &&
  process.env.EMAIL_FROM
);

const EMAIL_FROM = process.env.EMAIL_FROM || "no-reply@example.com";
let mailTransporter = null;

if (SMTP_ENABLED && nodemailer) {
  mailTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

/* ===========================
   Middleware
=========================== */
app.use(express.json({ limit: "1mb" }));
app.use(cors({ origin: "*", methods: ["GET", "POST", "OPTIONS"] }));
app.use(helmet({ contentSecurityPolicy: false }));
morgan.token("reqid", () => Math.random().toString(36).slice(2, 9));
app.use(morgan(":reqid :method :url :status :response-time ms"));

const limiter = rateLimit({
  windowMs: 10_000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/chat", limiter);
app.use("/site/request-demo", limiter);
app.use("/mascot/upload", limiter);

/* ===========================
   NEW ROUTES (SAFE)
=========================== */
app.use("/onboarding", onboardingRoutes);
app.use("/channels", channelRoutes);
app.use("/reports", reportsRoutes);

/* ===========================
   Plans
=========================== */
const PLAN_CONFIG = {
  basic: { dailyQuota: 50 },
  pro: { dailyQuota: null },
  advanced: { dailyQuota: null }
};

/* ===========================
   DB INIT (UNCHANGED)
=========================== */
let pool = null;
const db = {
  query: (q, p) => {
    if (!pool) throw new Error("DB not ready");
    return pool.query(q, p);
  }
};

function buildNeonConnectionString(raw) {
  if (!raw) return null;
  const u = new URL(raw.replace(/^['"]|['"]$/g, ""));
  u.searchParams.set("sslmode", "require");
  return u.toString();
}

(async function initDB() {
  if (!RAW_DATABASE_URL) return;
  const { Pool } = require("pg");
  pool = new Pool({
    connectionString: buildNeonConnectionString(RAW_DATABASE_URL),
    ssl: { rejectUnauthorized: false }
  });
})();
/* ===========================
   CHAT ENDPOINT (SAFE ENHANCED)
=========================== */
app.post("/chat", async (req, res) => {
  try {
    const userMessage = (req.body.message || "").trim();
    if (!userMessage) {
      return res.status(400).json({ error: "missing_message" });
    }

    const siteDomain =
      req.body.site ||
      (req.headers.origin ? new URL(req.headers.origin).hostname : null);

    if (!siteDomain) {
      return res.status(400).json({ error: "unknown_site" });
    }

    const siteRes = await db.query(
      "SELECT * FROM sites WHERE domain = $1",
      [siteDomain]
    );
    const site = siteRes.rows[0];
    if (!site) {
      return res.status(403).json({ error: "site_not_registered" });
    }

    const sessionId = req.body.sessionId || `anon-${Date.now()}`;

    /* --------- EXISTING AI LOGIC (UNCHANGED) --------- */
    const messages = [
      { role: "system", content: "You are a helpful website assistant." },
      { role: "user", content: userMessage }
    ];

    const aiResp = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      {
        model: "gpt-4o-mini",
        messages,
        temperature: 0.6,
        max_tokens: 500
      },
      {
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
          "Content-Type": "application/json"
        }
      }
    );

    const aiReply =
      aiResp.data?.choices?.[0]?.message?.content || "";

    /* --------- NEW: CHAT WORKFLOW (NON-BREAKING) --------- */
    let finalReply = aiReply;
    let ticketId = null;

    try {
      const wfResult = await chatWorkflow.handleChat({
        pool,
        site,
        channel: "web",
        sessionId,
        userMessage,
        aiReply,
        conversationLog: [
          { role: "user", text: userMessage },
          { role: "assistant", text: aiReply }
        ],
        contextUsed: false,
        customerContact: null
      });

      finalReply = wfResult.reply;
      ticketId = wfResult.ticketId || null;
    } catch (e) {
      console.warn("chat.workflow failed", e.message);
    }

    return res.json({
      reply: finalReply,
      ticketId,
      plan: site.plan,
      status: site.status
    });
  } catch (err) {
    console.error("Chat error", err);
    return res.status(500).json({ error: "server_error" });
  }
});
/* ===========================
   UPLOADS
=========================== */
const upload = multer({ storage: multer.memoryStorage() });
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

app.use("/uploads", express.static(UPLOAD_DIR));

app.post("/mascot/upload", upload.single("mascot"), (req, res) => {
  const filename = `${Date.now()}_${req.file.originalname}`;
  fs.writeFileSync(path.join(UPLOAD_DIR, filename), req.file.buffer);
  res.json({ url: `/uploads/${filename}` });
});

/* ===========================
   HEALTH
=========================== */
app.get("/", (_, res) => res.send("OK"));
app.get("/health", (_, res) =>
  res.json({ ok: true, time: new Date().toISOString() })
);

/* ===========================
   START SERVER
=========================== */
app.listen(PORT, () => {
  console.log(`✅ Mascot backend running on port ${PORT}`);
});
