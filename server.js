// server.js
// Mascot backend — FINAL STABLE VERSION
// Username-based admin login + Supabase/Neon safe DB connection

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const axios = require("axios");
const morgan = require("morgan");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");
require("dotenv").config();

/* ===========================
   WORKFLOWS & ROUTES
=========================== */
const chatWorkflow = require("./workflows/chat.workflow");
const onboardingRoutes = require("./routes/onboarding.routes");
const channelRoutes = require("./routes/channel.routes");
const reportsRoutes = require("./routes/reports.routes");

/* ===========================
   APP SETUP
=========================== */
const app = express();
app.set("trust proxy", true);

const PORT = process.env.PORT || 8080;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const RAW_DATABASE_URL = process.env.DATABASE_URL || "";

/* ===========================
   ADMIN AUTH CONFIG
=========================== */
const ADMIN_SECRET =
  process.env.ADMIN_SECRET ||
  process.env.ADMIN_JWT_SECRET ||
  "";

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password + ADMIN_SECRET)
    .digest("hex");
}

/* ===========================
   MIDDLEWARE
=========================== */
app.use(express.json({ limit: "1mb" }));
app.use(cors({ origin: "*", methods: ["GET", "POST", "OPTIONS"] }));
app.use(helmet({ contentSecurityPolicy: false }));

morgan.token("reqid", () => Math.random().toString(36).slice(2, 9));
app.use(morgan(":reqid :method :url :status :response-time ms"));

const limiter = rateLimit({
  windowMs: 10_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/chat", limiter);
app.use("/mascot/upload", limiter);
app.use("/admin/auth/login", limiter);

/* ===========================
   ROUTES
=========================== */
app.use("/onboarding", onboardingRoutes);
app.use("/channels", channelRoutes);
app.use("/reports", reportsRoutes);

/* ===========================
   DB INIT (NEON / SUPABASE SAFE)
=========================== */
let pool = null;

const db = {
  query: (q, p) => {
    if (!pool) throw new Error("DB not ready");
    return pool.query(q, p);
  }
};

// 🔴 IMPORTANT FIX: DO NOT MODIFY DATABASE_URL
function buildConnectionString(raw) {
  if (!raw) return null;
  return raw.replace(/^['"]|['"]$/g, "");
}

(async function initDB() {
  if (!RAW_DATABASE_URL) {
    console.warn("⚠️ DATABASE_URL not set");
    return;
  }

  const { Pool } = require("pg");

  pool = new Pool({
    connectionString: buildConnectionString(RAW_DATABASE_URL),
    ssl: { rejectUnauthorized: false }
  });

  console.log("✅ Database pool initialized");
})();

/* ===========================
   ADMIN LOGIN (USERNAME BASED)
=========================== */
app.post("/admin/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({
        error: "missing_credentials",
        message: "Username and password are required"
      });
    }

    const passwordHash = hashPassword(password);

    const result = await db.query(
      `SELECT id, username, role
       FROM admins
       WHERE username = $1
         AND password_hash = $2
       LIMIT 1`,
      [username, passwordHash]
    );

    const admin = result.rows[0];

    if (!admin) {
      return res.status(401).json({
        error: "invalid_credentials",
        message: "Invalid username or password"
      });
    }

    return res.json({
      success: true,
      admin: {
        id: admin.id,
        username: admin.username,
        role: admin.role
      }
    });
  } catch (err) {
    console.error("Admin login error:", err.message);
    return res.status(500).json({ error: "server_error" });
  }
});

/* ===========================
   CHAT ENDPOINT (UNCHANGED)
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
      console.warn("chat.workflow failed:", e.message);
    }

    return res.json({
      reply: finalReply,
      ticketId,
      plan: site.plan,
      status: site.status
    });
  } catch (err) {
    console.error("Chat error:", err.message);
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
