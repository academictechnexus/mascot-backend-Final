// server.js
// Mascot backend — FINAL VERSION (Neon + bcrypt + Railway safe)

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const axios = require("axios");
const morgan = require("morgan");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
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

/**
 * REQUIRED for Railway + Cloudflare
 * (fixes express-rate-limit warning)
 */
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const DATABASE_URL = process.env.DATABASE_URL || "";

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
   DATABASE (NEON DIRECT)
=========================== */
let pool = null;

const db = {
  query: (q, p) => {
    if (!pool) throw new Error("DB not ready");
    return pool.query(q, p);
  }
};

(async function initDB() {
  if (!DATABASE_URL) {
    console.error("❌ DATABASE_URL not set");
    return;
  }

  // 🔎 Log host once (helps confirm NOT pooler)
  console.log("🔎 DATABASE_URL HOST:", new URL(DATABASE_URL).host);

  const { Pool } = require("pg");
  pool = new Pool({ connectionString: DATABASE_URL });

  await pool.query("select 1");
  console.log("✅ Connected to Neon PostgreSQL");
})();

/* ===========================
   ADMIN LOGIN (bcrypt-based)
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

    const result = await db.query(
      `SELECT id, username, role, password_hash
       FROM admins
       WHERE username = $1
       LIMIT 1`,
      [username]
    );

    const admin = result.rows[0];

    if (!admin) {
      return res.status(401).json({
        error: "invalid_credentials",
        message: "Invalid username or password"
      });
    }

    const isValid = await bcrypt.compare(password, admin.password_hash);

    if (!isValid) {
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

    const aiResp = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      {
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: "You are a helpful website assistant." },
          { role: "user", content: userMessage }
        ],
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

    return res.json({
      reply: aiResp.data?.choices?.[0]?.message?.content || ""
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
