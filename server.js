// server.js
// Mascot backend — FULL ADMIN CONTROL ENABLED
// Railway + Cloudflare Pages + Neon + JWT VERIFIED

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
const jwt = require("jsonwebtoken");
const { URL } = require("url");
require("dotenv").config();

const adminAuth = require("./middleware/adminAuth");

/* ===========================
   APP SETUP
=========================== */
const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const DATABASE_URL = process.env.DATABASE_URL || "";
const JWT_SECRET = process.env.ADMIN_JWT_SECRET;

/* ===========================
   CORS (Cloudflare Safe)
=========================== */
app.use(
  cors({
    origin: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
  })
);

app.options("*", (_, res) => res.sendStatus(204));

/* ===========================
   MIDDLEWARE
=========================== */
app.use(express.json({ limit: "1mb" }));
app.use(helmet({ contentSecurityPolicy: false }));

morgan.token("reqid", () => Math.random().toString(36).slice(2, 9));
app.use(morgan(":reqid :method :url :status :response-time ms"));

/* ===========================
   RATE LIMITING
=========================== */
const limiter = rateLimit({
  windowMs: 10_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/chat", limiter);
app.use("/mascot/upload", limiter);

/* ===========================
   DATABASE (NEON)
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

  console.log("🔎 DATABASE_URL HOST:", new URL(DATABASE_URL).host);

  const { Pool } = require("pg");
  pool = new Pool({ connectionString: DATABASE_URL });

  await pool.query("select 1");
  console.log("✅ Connected to Neon PostgreSQL");
})();

/* ===========================
   MAKE DB AVAILABLE TO ROUTES
=========================== */
app.use((req, res, next) => {
  req.db = db;
  next();
});

/* ===========================
   ADMIN AUTH (PUBLIC)
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
      return res.status(401).json({ error: "invalid_credentials" });
    }

    const valid = await bcrypt.compare(password, admin.password_hash);
    if (!valid) {
      return res.status(401).json({ error: "invalid_credentials" });
    }

    const token = jwt.sign(
      {
        id: admin.id,
        username: admin.username,
        role: admin.role
      },
      JWT_SECRET,
      { expiresIn: "12h" }
    );

    res.json({
      success: true,
      token,
      admin: {
        id: admin.id,
        username: admin.username,
        role: admin.role
      }
    });
  } catch (err) {
    console.error("Admin login error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

/* ===========================
   ADMIN SESSION CHECK
=========================== */
app.get("/admin/me", adminAuth, (req, res) => {
  res.json({
    success: true,
    admin: req.admin
  });
});

/* ===========================
   ADMIN SITES MANAGEMENT (FULL CONTROL)
=========================== */

// Get all sites
app.get("/admin/sites", adminAuth, async (req, res) => {
  try {
    const { rows } = await req.db.query(
      `SELECT id, name, domain, plan, daily_quota, status, created_at
       FROM sites
       ORDER BY created_at DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error("GET sites error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// Create site
app.post("/admin/sites", adminAuth, async (req, res) => {
  try {
    const { name, domain, plan = "basic", daily_quota = 50, status = "active" } =
      req.body;

    if (!name || !domain) {
      return res.status(400).json({
        error: "missing_fields",
        message: "Name and domain are required"
      });
    }

    const { rows } = await req.db.query(
      `INSERT INTO sites (name, domain, plan, daily_quota, status)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [name, domain, plan, daily_quota, status]
    );

    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "duplicate_domain",
        message: "Domain already exists"
      });
    }

    console.error("CREATE site error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// Update site (plan / quota / name)
app.put("/admin/sites/:id", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, plan, daily_quota } = req.body;

    const { rows } = await req.db.query(
      `UPDATE sites
       SET
         name = COALESCE($1, name),
         plan = COALESCE($2, plan),
         daily_quota = COALESCE($3, daily_quota)
       WHERE id = $4
       RETURNING *`,
      [name, plan, daily_quota, id]
    );

    if (!rows[0]) {
      return res.status(404).json({ error: "site_not_found" });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error("UPDATE site error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// Enable / Disable site
app.patch("/admin/sites/:id/status", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!["active", "demo", "disabled"].includes(status)) {
      return res.status(400).json({ error: "invalid_status" });
    }

    const { rows } = await req.db.query(
      `UPDATE sites SET status = $1 WHERE id = $2 RETURNING *`,
      [status, id]
    );

    if (!rows[0]) {
      return res.status(404).json({ error: "site_not_found" });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error("UPDATE status error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

/* ===========================
   CHAT
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

    if (!siteRes.rows[0]) {
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

    res.json({
      reply: aiResp.data?.choices?.[0]?.message?.content || ""
    });
  } catch (err) {
    console.error("Chat error:", err);
    res.status(500).json({ error: "server_error" });
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
