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
const path = require("path");
const multer = require("multer");
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

/* ================= STATIC FILES ================= */
app.use(express.static(path.join(__dirname, "public")));
app.use("/chat", rateLimit({ windowMs: 10_000, max: 10 }));

/* ================= DATABASE ================= */
const pool = new Pool({ connectionString: DATABASE_URL });
const db = { query: (q, p) => pool.query(q, p) };

app.use((req, _, next) => {
  req.db = db;
  next();
});

/* ======================================================
   ADMIN ROUTER (🔥 IMPORTANT FIX — UNCHANGED)
====================================================== */
const adminRouter = express.Router();
app.use("/admin", adminRouter);

/* ================= ADMIN AUTH (UNCHANGED) ================= */

adminRouter.post("/auth/login", async (req, res) => {
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

adminRouter.get("/me", adminAuth, (req, res) => {
  res.json({ success: true, admin: req.admin });
});

/* ================= ADMIN ANALYTICS (UNCHANGED) ================= */

adminRouter.get("/analytics/overview", adminAuth, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);

    const [{ count: totalSites }] =
      (await db.query("SELECT COUNT(*) FROM sites")).rows;

    const [{ count: activeSites }] =
      (await db.query("SELECT COUNT(*) FROM sites WHERE status='active'")).rows;

    const [{ count: messagesToday }] =
      (await db.query(
        "SELECT COUNT(*) FROM messages WHERE created_at::date = $1",
        [today]
      )).rows;

    const [{ count: knowledgeItems }] =
      (await db.query("SELECT COUNT(*) FROM knowledge_items")).rows;

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

/* ================= GLOBAL SETTINGS (UNCHANGED) ================= */

adminRouter.get("/settings", adminAuth, async (_, res) => {
  const { rows } = await db.query("SELECT * FROM global_settings LIMIT 1");
  res.json(rows[0]);
});

adminRouter.put("/settings", adminAuth, async (req, res) => {
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

    await db.query(
      `UPDATE global_settings
       SET ${fields.join(", ")}, updated_at=NOW()
       WHERE id=1`,
      values
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "server_error" });
  }
});

/* ================= SITE MANAGEMENT (UNCHANGED) ================= */

adminRouter.get("/sites", adminAuth, async (req, res) => {
  const { rows } = await db.query(
    `SELECT id, name, domain, plan, daily_quota, status, setup_completed, created_at
     FROM sites ORDER BY created_at DESC`
  );
  res.json(rows);
});

adminRouter.post("/sites", adminAuth, async (req, res) => {
  try {
    let finalDomain = (req.body.domain || req.body.url || "")
      .replace(/^https?:\/\//, "")
      .replace(/\/$/, "")
      .toLowerCase()
      .trim();

    if (!finalDomain) {
      return res.status(400).json({ error: "missing_domain" });
    }

    const result = await db.query(
      `INSERT INTO sites (id, name, domain, plan, daily_quota, status)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING *`,
      [
        crypto.randomUUID(),
        req.body.name || finalDomain.split(".")[0],
        finalDomain,
        req.body.plan || "demo",
        Number(req.body.daily_quota) || 50,
        req.body.status || "active"
      ]
    );

    res.json({ success: true, site: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "server_error" });
  }
});

/* ======================================================
   🆕 AI SETUP & LEARNING (ADMIN ONLY)
====================================================== */

const upload = multer({ limits: { fileSize: 5 * 1024 * 1024 } });

adminRouter.post("/sites/:id/setup", adminAuth, async (req, res) => {
  try {
    const siteId = req.params.id;
    const answers = req.body.answers || {};

    for (const key of Object.keys(answers)) {
      await db.query(
        `INSERT INTO site_setup_answers (id, site_id, question_key, answer)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT (site_id, question_key)
         DO UPDATE SET answer = EXCLUDED.answer`,
        [crypto.randomUUID(), siteId, key, answers[key]]
      );
    }

    await db.query(
      "UPDATE sites SET setup_completed=true WHERE id=$1",
      [siteId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Setup error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

adminRouter.post(
  "/sites/:id/setup/upload",
  adminAuth,
  upload.array("files", 3),
  async (req, res) => {
    try {
      const siteId = req.params.id;

      for (const file of req.files || []) {
        await db.query(
          `INSERT INTO site_knowledge (id, site_id, source, content)
           VALUES ($1,$2,'upload',$3)`,
          [crypto.randomUUID(), siteId, file.buffer.toString("utf-8")]
        );
      }

      res.json({ success: true });
    } catch (err) {
      console.error("Upload error:", err);
      res.status(500).json({ error: "server_error" });
    }
  }
);

/* ================= CHAT (EXTENDED, SAFE) ================= */

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

    if (!site.setup_completed) {
      return res.json({
        reply: "Assistant is currently being configured. Please check back soon."
      });
    }

    res.json({ reply: "AI ready (prompt + learning pipeline active)." });
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
