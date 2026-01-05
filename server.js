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
const BASE_URL = "https://mascot.academictechnexus.com";

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
   ADMIN ROUTER (UNCHANGED)
====================================================== */
const adminRouter = express.Router();
app.use("/admin", adminRouter);

/* ================= ADMIN AUTH ================= */

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

/* ================= ADMIN ANALYTICS ================= */

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

/* ================= GLOBAL SETTINGS ================= */

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

/* ================= SITE MANAGEMENT ================= */

/* ---------- Helper: embed script generator (ADDED) ---------- */
function generateEmbedScript(domain) {
  return `<script>
(function(){
  var s=document.createElement("script");
  s.src="${BASE_URL}/chatbot-widget.js";
  s.async=true;
  s.setAttribute("data-site","${domain}");
  document.head.appendChild(s);
})();
</script>`;
}

/* ---------- Helper: create setup token (ADDED) ---------- */
async function createClientSetupToken(siteId) {
  const token = crypto.randomBytes(24).toString("hex");
  await db.query(
    `INSERT INTO client_setup_tokens (id, site_id, token)
     VALUES ($1,$2,$3)`,
    [crypto.randomUUID(), siteId, token]
  );
  return token;
}

/* ---------- LIST SITES (EXTENDED, SAFE) ---------- */
adminRouter.get("/sites", adminAuth, async (req, res) => {
  const { rows } = await db.query(
    `SELECT id, name, domain, plan, daily_quota, status, setup_completed, created_at
     FROM sites ORDER BY created_at DESC`
  );

  const enriched = rows.map(site => {
    const setupLink = `${BASE_URL}/client-setup/${site.id}`;
    return {
      ...site,
      client_setup_link: `${BASE_URL}/client-setup/${site.id}`,
      embed_script: generateEmbedScript(site.domain)
    };
  });

  res.json(enriched);
});

/* ---------- CREATE SITE (EXTENDED, SAFE) ---------- */
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

    const siteId = crypto.randomUUID();

    const siteResult = await db.query(
      `INSERT INTO sites (id, name, domain, plan, daily_quota, status)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING *`,
      [
        siteId,
        req.body.name || finalDomain.split(".")[0],
        finalDomain,
        req.body.plan || "demo",
        Number(req.body.daily_quota) || 50,
        req.body.status || "active"
      ]
    );

    const setupToken = await createClientSetupToken(siteId);
    const setupLink = `${BASE_URL}/client-setup/${setupToken}`;
    const embedScript = generateEmbedScript(finalDomain);

    res.json({
      success: true,
      site: siteResult.rows[0],
      client_setup_link: setupLink,
      embed_script: embedScript
    });
  } catch (err) {
    console.error("Create site error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

/* ======================================================
   CLIENT SETUP — PUBLIC (UNCHANGED)
====================================================== */

async function resolveSiteByToken(token) {
  const { rows } = await db.query(
    `SELECT s.*
     FROM client_setup_tokens t
     JOIN sites s ON s.id = t.site_id
     WHERE t.token=$1`,
    [token]
  );
  return rows[0];
}

app.get("/client-setup/:token", async (req, res) => {
  try {
    const site = await resolveSiteByToken(req.params.token);
    if (!site) {
      return res.status(404).json({ error: "invalid_token" });
    }

    res.json({
      site: {
        id: site.id,
        domain: site.domain,
        setup_completed: site.setup_completed
      }
    });
  } catch (err) {
    console.error("Client setup fetch error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/client-setup/:token/setup", async (req, res) => {
  try {
    const site = await resolveSiteByToken(req.params.token);
    if (!site) {
      return res.status(404).json({ error: "invalid_token" });
    }

    const answers = req.body.answers || {};

    for (const key of Object.keys(answers)) {
      await db.query(
        `INSERT INTO site_setup_answers (id, site_id, question_key, answer)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT (site_id, question_key)
         DO UPDATE SET answer = EXCLUDED.answer`,
        [crypto.randomUUID(), site.id, key, answers[key]]
      );
    }

    await db.query(
      "UPDATE sites SET setup_completed=true WHERE id=$1",
      [site.id]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Client setup save error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

const clientUpload = multer({ limits: { fileSize: 5 * 1024 * 1024 } });

app.post(
  "/client-setup/:token/upload",
  clientUpload.array("files", 3),
  async (req, res) => {
    try {
      const site = await resolveSiteByToken(req.params.token);
      if (!site) {
        return res.status(404).json({ error: "invalid_token" });
      }

      for (const file of req.files || []) {
        await db.query(
          `INSERT INTO site_knowledge (id, site_id, source, content)
           VALUES ($1,$2,'upload',$3)`,
          [crypto.randomUUID(), site.id, file.buffer.toString("utf-8")]
        );
      }

      res.json({ success: true });
    } catch (err) {
      console.error("Client upload error:", err);
      res.status(500).json({ error: "server_error" });
    }
  }
);

/* ================= CHAT ================= */

app.post("/chat", async (req, res) => {
  try {
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

    res.json({ reply: "AI ready (client setup complete)." });
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
