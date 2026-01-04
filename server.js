// server.js
// Mascot backend — FULL AI SAAS ENGINE (FINAL, SAFE, ENTERPRISE + ANALYTICS)

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const axios = require("axios");
const morgan = require("morgan");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const { URL } = require("url");
const crypto = require("crypto");
const path = require("path"); // ✅ ADDED (STATIC FILE SUPPORT)
require("dotenv").config();

const adminAuth = require("./middleware/adminAuth");

/* ================= SETUP ================= */
const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.ADMIN_JWT_SECRET;

/* ================= MIDDLEWARE ================= */
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "1mb" }));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan("dev"));

/* ================= STATIC FILES (ONLY FIX) ================= */
app.use(express.static(path.join(__dirname, "public"))); // ✅ exposes /chatbot-widget.js

app.use("/chat", rateLimit({ windowMs: 10_000, max: 10 }));

/* ================= DATABASE ================= */
const pool = new Pool({ connectionString: DATABASE_URL });
const db = { query: (q, p) => pool.query(q, p) };

app.use((req, _, next) => {
  req.db = db;
  next();
});

/* ================= ADMIN LOGIN ================= */
app.post("/admin/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const { rows } = await db.query(
      "SELECT * FROM admins WHERE username=$1 LIMIT 1",
      [username]
    );

    const admin = rows[0];
    if (!admin || !(await bcrypt.compare(password, admin.password_hash))) {
      return res.status(401).json({ error: "invalid_credentials" });
    }

    const token = jwt.sign(
      { id: admin.id, role: admin.role },
      JWT_SECRET,
      { expiresIn: "12h" }
    );

    res.json({
      success: true,
      token,
      admin: { id: admin.id, username: admin.username, role: admin.role }
    });
  } catch (err) {
    console.error("Admin login error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

/* ================= ADMIN SESSION ================= */
app.get("/admin/me", adminAuth, (req, res) => {
  res.json({ success: true, admin: req.admin });
});

/* ================= ADMIN ANALYTICS ================= */

app.get("/admin/analytics/overview", adminAuth, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);

    const [{ count: totalSites }] = (
      await db.query("SELECT COUNT(*) FROM sites")
    ).rows;

    const [{ count: activeSites }] = (
      await db.query("SELECT COUNT(*) FROM sites WHERE status='active'")
    ).rows;

    const [{ count: messagesToday }] = (
      await db.query(
        "SELECT COUNT(*) FROM messages WHERE created_at::date = $1",
        [today]
      )
    ).rows;

    const [{ count: knowledgeItems }] = (
      await db.query("SELECT COUNT(*) FROM knowledge_items")
    ).rows;

    res.json({
      totalSites: Number(totalSites),
      activeSites: Number(activeSites),
      messagesToday: Number(messagesToday),
      knowledgeItems: Number(knowledgeItems)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "server_error" });
  }
});

app.get("/admin/analytics/sites", adminAuth, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);

    const { rows } = await db.query(
      `
      SELECT
        s.id,
        s.domain,
        s.plan,
        s.daily_quota,
        s.status,
        COALESCE(u.count, 0) AS usage_today
      FROM sites s
      LEFT JOIN usage_daily u
        ON u.site_id = s.id AND u.date = $1
      ORDER BY usage_today DESC
      `,
      [today]
    );

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "server_error" });
  }
});

/* ================= GLOBAL SETTINGS ================= */

app.get("/admin/settings", adminAuth, async (_, res) => {
  const { rows } = await db.query("SELECT * FROM global_settings LIMIT 1");
  res.json(rows[0]);
});

app.put("/admin/settings", adminAuth, async (req, res) => {
  try {
    const allowed = [
      "demo_days",
      "demo_daily_quota",
      "ai_enabled",
      "learning_enabled",
      "tone",
      "temperature",
      "max_tokens",
      "system_prompt",
      "blocked_topics"
    ];

    const fields = [];
    const values = [];
    let i = 1;

    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        fields.push(`${key}=$${i++}`);
        values.push(req.body[key]);
      }
    }

    if (!fields.length) {
      return res.status(400).json({ error: "no_valid_fields" });
    }

    values.push(true);

    await db.query(
      `UPDATE global_settings
       SET ${fields.join(", ")}, updated_at=NOW()
       WHERE id=$${i}`,
      values
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "server_error" });
  }
});

/* ================= SITE MANAGEMENT ================= */

// Create site (Option-B compatible)
app.post("/admin/sites", adminAuth, async (req, res) => {
  try {
    const {
      name,
      siteName,
      domain,
      url,
      plan,
      daily_quota,
      status,
      webhook_url
    } = req.body;

    let finalDomain = domain || url;
    if (finalDomain) {
      finalDomain = finalDomain
        .replace(/^https?:\/\//, "")
        .replace(/\/$/, "")
        .toLowerCase()
        .trim();
    }

    const finalName =
      name ||
      siteName ||
      (finalDomain ? finalDomain.split(".")[0] : null);

    if (!finalName || !finalDomain) {
      return res.status(400).json({
        error: "missing_required_fields",
        required: ["domain"]
      });
    }

    const result = await db.query(
      `
      INSERT INTO sites (
        id,
        name,
        domain,
        plan,
        daily_quota,
        status,
        webhook_url
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      RETURNING *
      `,
      [
        crypto.randomUUID(),
        finalName.trim(),
        finalDomain,
        plan || "free",
        Number(daily_quota) || 100,
        status || "active",
        webhook_url || null
      ]
    );

    res.json({ success: true, site: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(400).json({ error: "site_already_exists" });
    }
    console.error("Create site error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

/* ================= CHAT (CORE ENGINE — UNCHANGED) ================= */

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
      "SELECT * FROM sites WHERE domain=$1",
      [siteDomain]
    );
    const site = siteRes.rows[0];
    if (!site) {
      return res.status(403).json({ error: "site_not_registered" });
    }

    res.json({ reply: "OK" });
  } catch (err) {
    console.error("Chat error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

/* ================= HEALTH ================= */
app.get("/", (_, res) => res.send("OK"));
app.get("/health", (_, res) =>
  res.json({ ok: true, time: new Date().toISOString() })
);

/* ================= START ================= */
app.listen(PORT, () => {
  console.log(`✅ Mascot backend running on port ${PORT}`);
});
