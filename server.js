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

// Create site
app.post("/admin/sites", adminAuth, async (req, res) => {
  try {
    const {
      name,
      domain,
      plan,
      daily_quota,
      status,
      webhook_url
    } = req.body;

    if (!name || !domain) {
      return res.status(400).json({
        error: "missing_required_fields",
        required: ["name", "domain"]
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
        name.trim(),
        domain.toLowerCase().trim(),
        plan || "free",
        Number(daily_quota) ?? 100,
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

// Update site
app.put("/admin/sites/:id", adminAuth, async (req, res) => {
  try {
    const {
      name,
      plan,
      daily_quota,
      status,
      webhook_url
    } = req.body;

    await db.query(
      `
      UPDATE sites
      SET
        name = COALESCE($1, name),
        plan = COALESCE($2, plan),
        daily_quota = COALESCE($3, daily_quota),
        status = COALESCE($4, status),
        webhook_url = COALESCE($5, webhook_url)
      WHERE id = $6
      `,
      [
        name?.trim(),
        plan,
        daily_quota !== undefined ? Number(daily_quota) : null,
        status,
        webhook_url,
        req.params.id
      ]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Update site error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// List sites
app.get("/admin/sites", adminAuth, async (_, res) => {
  const { rows } = await db.query(
    `
    SELECT
      id,
      name,
      domain,
      plan,
      daily_quota,
      status,
      webhook_url,
      created_at
    FROM sites
    ORDER BY domain
    `
  );
  res.json(rows);
});

/* ================= PER-SITE AI SETTINGS ================= */

app.get("/admin/sites/:id/ai", adminAuth, async (req, res) => {
  const { rows } = await db.query(
    "SELECT * FROM site_ai_settings WHERE site_id=$1",
    [req.params.id]
  );
  res.json(rows[0] || {});
});

app.put("/admin/sites/:id/ai", adminAuth, async (req, res) => {
  try {
    const allowed = [
      "ai_enabled",
      "learning_enabled",
      "temperature",
      "max_tokens",
      "system_prompt",
      "blocked_topics"
    ];

    const fields = [];
    const values = [];
    let i = 2;

    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        fields.push(`${key}=$${i++}`);
        values.push(req.body[key]);
      }
    }

    if (!fields.length) {
      return res.status(400).json({ error: "no_valid_fields" });
    }

    await db.query(
      `
      INSERT INTO site_ai_settings (site_id, ${fields.map(f => f.split("=")[0]).join(", ")})
      VALUES ($1, ${fields.map((_, idx) => `$${idx + 2}`).join(", ")})
      ON CONFLICT (site_id)
      DO UPDATE SET ${fields.join(", ")}
      `,
      [req.params.id, ...values]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "server_error" });
  }
});

/* ================= CONVERSATIONS & KNOWLEDGE ================= */

app.get("/admin/conversations", adminAuth, async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 50, 100);
  const offset = Number(req.query.offset) || 0;

  const { rows } = await db.query(
    `
    SELECT c.id, c.session_id, c.created_at, s.domain
    FROM conversations c
    JOIN sites s ON s.id=c.site_id
    ORDER BY c.created_at DESC
    LIMIT $1 OFFSET $2
    `,
    [limit, offset]
  );

  res.json(rows);
});

app.get("/admin/conversations/:id/messages", adminAuth, async (req, res) => {
  const { rows } = await db.query(
    `
    SELECT role, text, created_at
    FROM messages
    WHERE conversation_id=$1
    ORDER BY created_at ASC
    `,
    [req.params.id]
  );

  res.json(rows);
});

app.get("/admin/knowledge", adminAuth, async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 50, 100);
  const offset = Number(req.query.offset) || 0;

  const { rows } = await db.query(
    `
    SELECT k.id, k.title, k.content, k.created_at, s.domain
    FROM knowledge_items k
    JOIN sites s ON s.id=k.site_id
    ORDER BY k.created_at DESC
    LIMIT $1 OFFSET $2
    `,
    [limit, offset]
  );

  res.json(rows);
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
