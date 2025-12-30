// server.js
// Mascot backend — FULL AI SAAS ENGINE (FINAL, SAFE, ENTERPRISE)

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

app.use(
  "/chat",
  rateLimit({ windowMs: 10_000, max: 10 })
);

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

/* ================= CHAT (CORE ENGINE) ================= */
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

    /* -------- Site -------- */
    const siteRes = await db.query(
      "SELECT * FROM sites WHERE domain=$1",
      [siteDomain]
    );
    const site = siteRes.rows[0];
    if (!site) {
      return res.status(403).json({ error: "site_not_registered" });
    }

    /* -------- Global Settings -------- */
    const global = (
      await db.query("SELECT * FROM global_settings LIMIT 1")
    ).rows[0];

    /* -------- Site AI Override -------- */
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

    /* -------- Usage & Quota -------- */
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

    /* -------- Conversation -------- */
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

    /* -------- Store User Message -------- */
    await db.query(
      `INSERT INTO messages (conversation_id, role, text)
       VALUES ($1,'user',$2)`,
      [convo.id, userMessage]
    );

    /* -------- OpenAI Call -------- */
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

    /* -------- Store AI Message -------- */
    await db.query(
      `INSERT INTO messages (conversation_id, role, text)
       VALUES ($1,'assistant',$2)`,
      [convo.id, reply]
    );

    /* -------- Increment Usage -------- */
    await db.query(
      `UPDATE usage_daily
       SET count = count + 1
       WHERE site_id=$1 AND date=$2`,
      [site.id, today]
    );

    /* -------- SAFE SELF-LEARNING -------- */
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
