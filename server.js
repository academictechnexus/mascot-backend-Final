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

/* ================= SITE MANAGEMENT (NEW – REQUIRED) ================= */

// Create site
app.post("/admin/sites", adminAuth, async (req, res) => {
  try {
    const { domain, plan, daily_quota, status } = req.body;

    if (!domain || !plan) {
      return res.status(400).json({ error: "missing_fields" });
    }

    const result = await db.query(
      `
      INSERT INTO sites (domain, plan, daily_quota, status)
      VALUES ($1,$2,$3,$4)
      RETURNING *
      `,
      [
        domain.toLowerCase().trim(),
        plan,
        Number(daily_quota) || 0,
        status || "active"
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

// Update site (plan / quota / status)
app.put("/admin/sites/:id", adminAuth, async (req, res) => {
  try {
    const { plan, daily_quota, status } = req.body;

    await db.query(
      `
      UPDATE sites
      SET plan=$1,
          daily_quota=$2,
          status=$3
      WHERE id=$4
      `,
      [plan, Number(daily_quota), status, req.params.id]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Update site error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

/* ================= PER-SITE AI SETTINGS ================= */

app.get("/admin/sites", adminAuth, async (_, res) => {
  const { rows } = await db.query(
    "SELECT id, domain, plan, daily_quota, status FROM sites ORDER BY domain"
  );
  res.json(rows);
});

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

    const global = (
      await db.query("SELECT * FROM global_settings LIMIT 1")
    ).rows[0];

    const siteAI = (
      await db.query(
        "SELECT * FROM site_ai_settings WHERE site_id=$1",
        [site.id]
      )
    ).rows[0] || {};

    const ai = {
      enabled: siteAI.ai_enabled ?? global.ai_enabled,
      learning: siteAI.learning_enabled ?? global.learning_enabled,
      temperature: siteAI.temperature ?? global.temperature,
      max_tokens: siteAI.max_tokens ?? global.max_tokens,
      system_prompt: siteAI.system_prompt ?? global.system_prompt,
      blocked_topics: siteAI.blocked_topics ?? global.blocked_topics
    };

    if (!ai.enabled) {
      return res.json({ reply: "AI assistant is currently disabled." });
    }

    if (
      ai.blocked_topics &&
      ai.blocked_topics
        .split(",")
        .some(t => userMessage.toLowerCase().includes(t.trim()))
    ) {
      return res.json({ reply: "I can’t help with this topic." });
    }

    const today = new Date().toISOString().slice(0, 10);

    await db.query(
      `INSERT INTO usage_daily (site_id, date, count)
       VALUES ($1,$2,0)
       ON CONFLICT (site_id,date) DO NOTHING`,
      [site.id, today]
    );

    const usage = (
      await db.query(
        "SELECT count FROM usage_daily WHERE site_id=$1 AND date=$2",
        [site.id, today]
      )
    ).rows[0];

    const quota =
      site.status === "demo"
        ? global.demo_daily_quota
        : site.daily_quota;

    if (usage.count >= quota) {
      return res.json({
        reply: "Daily message limit reached. Please try again tomorrow."
      });
    }

    const sessionId = req.body.session || "anon";

    let convo = (
      await db.query(
        `SELECT * FROM conversations
         WHERE site_id=$1 AND session_id=$2`,
        [site.id, sessionId]
      )
    ).rows[0];

    if (!convo) {
      convo = (
        await db.query(
          `INSERT INTO conversations (site_id, session_id)
           VALUES ($1,$2) RETURNING *`,
          [site.id, sessionId]
        )
      ).rows[0];
    }

    await db.query(
      `INSERT INTO messages (conversation_id, role, text)
       VALUES ($1,'user',$2)`,
      [convo.id, userMessage]
    );

    const aiResp = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      {
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: ai.system_prompt },
          { role: "user", content: userMessage }
        ],
        temperature: ai.temperature,
        max_tokens: ai.max_tokens
      },
      {
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
          "Content-Type": "application/json"
        }
      }
    );

    const reply =
      aiResp.data?.choices?.[0]?.message?.content || "";

    await db.query(
      `INSERT INTO messages (conversation_id, role, text)
       VALUES ($1,'assistant',$2)`,
      [convo.id, reply]
    );

    await db.query(
      `UPDATE usage_daily
       SET count = count + 1
       WHERE site_id=$1 AND date=$2`,
      [site.id, today]
    );

    if (ai.learning) {
      const msgCount = (
        await db.query(
          "SELECT COUNT(*) FROM messages WHERE conversation_id=$1",
          [convo.id]
        )
      ).rows[0].count;

      if (msgCount >= 10 && !convo.last_summary_at) {
        const summaryResp = await axios.post(
          "https://api.openai.com/v1/chat/completions",
          {
            model: "gpt-4o-mini",
            messages: [
              {
                role: "system",
                content:
                  "Summarize the key facts and knowledge from this conversation."
              }
            ],
            max_tokens: 200
          },
          {
            headers: {
              Authorization: `Bearer ${OPENAI_API_KEY}`,
              "Content-Type": "application/json"
            }
          }
        );

        const summary =
          summaryResp.data?.choices?.[0]?.message?.content;

        if (summary) {
          await db.query(
            `INSERT INTO knowledge_items (site_id, title, content)
             VALUES ($1,'Conversation Summary',$2)`,
            [site.id, summary]
          );

          await db.query(
            `UPDATE conversations
             SET last_summary_at = NOW(), summary=$2
             WHERE id=$1`,
            [convo.id, summary]
          );
        }
      }
    }

    res.json({ reply });
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
