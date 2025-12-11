// server.js
// Mascot backend — enhanced: email confirmation, optional reCAPTCHA, Stripe checkout scaffold,
// demo request/activation + demo limits, SNI-friendly Neon init, leads, RAG, usage tracking.
//
// Required env:
// - DATABASE_URL, OPENAI_API_KEY
// Optional env (enable features):
// - SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, EMAIL_FROM   -> enable email confirmation
// - RECAPTCHA_SECRET                                         -> enable recaptcha check on demo request
// - STRIPE_SECRET_KEY                                        -> enable Stripe Checkout scaffold
// - PGHOST_IPV4, DEMO_DAYS, RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX

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

// Optional libs (only used if env provided)
let nodemailer = null;
try { nodemailer = require("nodemailer"); } catch (e) {}
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  try { stripe = require("stripe")(process.env.STRIPE_SECRET_KEY); } catch (e) { stripe = null; console.warn("Stripe lib not installed or invalid key"); }
}

const app = express();
app.set("trust proxy", true);

const PORT = process.env.PORT || 8080;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const RAW_DATABASE_URL = process.env.DATABASE_URL || "";
const PGHOST_IPV4 = process.env.PGHOST_IPV4 || "";
const DEMO_DAYS = parseInt(process.env.DEMO_DAYS || "7", 10);
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || null;

// Email config (optional)
const SMTP_ENABLED = !!(process.env.SMTP_HOST && process.env.SMTP_PORT && process.env.SMTP_USER && process.env.SMTP_PASS && process.env.EMAIL_FROM);
const EMAIL_FROM = process.env.EMAIL_FROM || "no-reply@example.com";

let mailTransporter = null;
if (SMTP_ENABLED && nodemailer) {
  mailTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || "587", 10),
    secure: parseInt(process.env.SMTP_PORT || "587", 10) === 465, // true for 465
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
  console.log("ℹ️ SMTP email enabled for demo confirmation.");
} else if (SMTP_ENABLED) {
  console.warn("⚠️ SMTP config present but nodemailer not installed. Email confirmation won't work.");
}

// Basic middlewares
app.use(express.json({ limit: "1mb" }));
app.use(cors({ origin: "*", methods: ["GET","POST","OPTIONS"], allowedHeaders: ["Content-Type","Authorization"] }));
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: "cross-origin" } }));
morgan.token("reqid", () => Math.random().toString(36).slice(2, 9));
app.use(morgan(":reqid :method :url :status - :response-time ms", { skip: (r) => r.path === "/health" }));

// Rate limiters
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "10000", 10),
  max: parseInt(process.env.RATE_LIMIT_MAX || "8", 10),
  standardHeaders: true, legacyHeaders: false
});
app.use("/chat", limiter);
app.use("/site/request-demo", limiter);
app.use("/mascot/upload", limiter);

// ---------- Plans & config ----------
const PLAN_CONFIG = {
  basic: { name: "Basic", dailyQuota: 50, features: { fullRag: false, summary: false, uploads: false } },
  pro: { name: "Pro", dailyQuota: null, features: { fullRag: true, summary: false, uploads: true } },
  advanced: { name: "Advanced", dailyQuota: null, features: { fullRag: true, summary: true, uploads: true } }
};

// ---------- DB init (Neon-aware, SNI friendly) ----------
let pool = null;
const db = { query: (text, params) => { if (!pool) throw new Error("Postgres pool not initialized yet"); return pool.query(text, params); }};

function buildNeonConnectionString(raw) {
  if (!raw) return null;
  let u = raw.trim().replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1");
  let parsed;
  try { parsed = new URL(u); } catch (e) { console.error("Invalid DATABASE_URL:", e.message); return null; }
  const originalHost = parsed.hostname;
  const firstLabel = originalHost.split(".")[0] || "";
  const endpointId = firstLabel;
  const params = parsed.searchParams;
  if (!params.has("sslmode")) params.set("sslmode", "require");
  if (endpointId) params.set("options", `endpoint=${endpointId}`);
  parsed.search = params.toString();
  return parsed.toString();
}

(async function initPostgresPool() {
  try {
    if (!RAW_DATABASE_URL) { console.warn("⚠️ DATABASE_URL not set — pool cannot be created."); return; }
    const parsedRaw = (() => { try { return new URL(RAW_DATABASE_URL.trim().replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1")); } catch (e) { console.error("❌ Invalid RAW DATABASE_URL:", e.message); return null; } })();
    if (!parsedRaw) return;
    const originalHost = parsedRaw.hostname;
    try {
      const addrs = await dns.resolve4(originalHost);
      if (Array.isArray(addrs) && addrs.length) console.log("✅ Resolved DB IPv4 via resolve4:", originalHost, "->", addrs[0]);
    } catch (_) {}
    const finalConnString = buildNeonConnectionString(RAW_DATABASE_URL);
    console.log("🔍 RAW process.env.DATABASE_URL:", JSON.stringify(RAW_DATABASE_URL));
    console.log("🔧 Final DATABASE_URL used (password redacted):", finalConnString ? finalConnString.replace(/:\/\/([^:]+):([^@]+)@/, "://$1:REDACTED@") : null);
    if (!finalConnString) return;
    const { Pool } = require("pg");
    const sslOptions = { rejectUnauthorized: false };
    try { if (parsedRaw && parsedRaw.hostname) sslOptions.servername = parsedRaw.hostname; } catch (e) {}
    pool = new Pool({ connectionString: finalConnString, ssl: sslOptions, allowExitOnIdle: true });

    // Create tables if missing and patch demo_request columns if required
    const ensureSql = `
      CREATE EXTENSION IF NOT EXISTS pgcrypto;
      CREATE TABLE IF NOT EXISTS sites (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL,
        domain TEXT NOT NULL UNIQUE,
        plan TEXT NOT NULL DEFAULT 'basic',
        daily_quota INTEGER NOT NULL DEFAULT 50,
        status TEXT NOT NULL DEFAULT 'active',
        webhook_url TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        demo_expires TIMESTAMPTZ,
        demo_message_limit INTEGER,
        demo_message_used INTEGER DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS conversations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        session_id TEXT NOT NULL,
        summary TEXT,
        last_summary_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        role TEXT NOT NULL,
        text TEXT NOT NULL,
        page_url TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS usage_daily (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        date DATE NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        CONSTRAINT unique_site_date UNIQUE (site_id, date)
      );
      CREATE TABLE IF NOT EXISTS knowledge_items (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS demo_requests (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT NOT NULL,
        requested_domain TEXT,
        token TEXT NOT NULL UNIQUE,
        plan TEXT DEFAULT 'basic',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        activated BOOLEAN DEFAULT FALSE,
        activated_at TIMESTAMPTZ,
        activated_domain TEXT,
        email_confirm_token TEXT,
        email_confirmed BOOLEAN DEFAULT FALSE
      );
      CREATE TABLE IF NOT EXISTS leads (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        site_id UUID REFERENCES sites(id) ON DELETE SET NULL,
        name TEXT,
        email TEXT,
        message TEXT,
        page_url TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `;
    await pool.query(ensureSql);

    // ensure demo_requests has columns (some Postgres setups might skip)
    try {
      await pool.query("ALTER TABLE demo_requests ADD COLUMN IF NOT EXISTS email_confirm_token TEXT");
      await pool.query("ALTER TABLE demo_requests ADD COLUMN IF NOT EXISTS email_confirmed BOOLEAN DEFAULT FALSE");
    } catch (e) { /* ignore */ }

    await pool.query("SELECT 1");
    console.log("✅ Postgres pool created and reachable (final host used):", parsedRaw.hostname);
  } catch (err) {
    console.error("❌ Failed to create Postgres pool:", err && err.message ? err.message : err);
  }
})();

// ---------- DB helpers ----------
async function getSiteByDomain(domain) {
  if (!domain) return null;
  const r = await db.query("SELECT * FROM sites WHERE domain = $1", [domain]);
  const site = r.rows[0];
  if (!site) return null;
  if (site.status === "demo" && site.demo_expires) {
    const exp = new Date(site.demo_expires);
    if (isNaN(exp.getTime()) || exp.getTime() < Date.now()) return null;
  }
  return site;
}

async function createSiteDemo(domain, name = null, plan = "basic", demoDays = DEMO_DAYS) {
  const demoLimit = 10;
  const expires = new Date(Date.now() + demoDays * 24 * 60 * 60 * 1000).toISOString();
  const planConf = PLAN_CONFIG[plan] ? plan : "basic";
  const daily_quota = PLAN_CONFIG[planConf].dailyQuota || 50;
  const r = await db.query(
    `INSERT INTO sites (id, name, domain, plan, daily_quota, status, created_at, demo_expires, demo_message_limit, demo_message_used)
     VALUES (gen_random_uuid(), $1, $2, $3, $4, 'demo', NOW(), $5, $6, 0)
     ON CONFLICT (domain) DO UPDATE SET
        name = EXCLUDED.name,
        plan = EXCLUDED.plan,
        daily_quota = EXCLUDED.daily_quota,
        status = 'demo',
        demo_expires = EXCLUDED.demo_expires,
        demo_message_limit = EXCLUDED.demo_message_limit,
        demo_message_used = 0
     RETURNING *`,
    [name || `Demo - ${domain}`, domain, planConf, daily_quota, expires, demoLimit]
  );
  return r.rows[0];
}

async function createDemoRequest(email, requestedDomain = null, plan = "basic") {
  const token = crypto.randomBytes(20).toString("hex");
  const emailConfirmToken = crypto.randomBytes(20).toString("hex");
  const r = await db.query(
    `INSERT INTO demo_requests (email, requested_domain, token, plan, email_confirm_token) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [email, requestedDomain, token, plan, emailConfirmToken]
  );
  return r.rows[0];
}

async function getDemoRequestByToken(token) {
  const r = await db.query("SELECT * FROM demo_requests WHERE token = $1", [token]);
  return r.rows[0];
}

async function getDemoRequestByEmailConfirmToken(token) {
  const r = await db.query("SELECT * FROM demo_requests WHERE email_confirm_token = $1", [token]);
  return r.rows[0];
}

async function markDemoRequestEmailConfirmed(id) {
  const r = await db.query("UPDATE demo_requests SET email_confirmed = true WHERE id = $1 RETURNING *", [id]);
  return r.rows[0];
}

async function activateDemoRequest(token, detectedDomain) {
  const now = new Date().toISOString();
  const r = await db.query("UPDATE demo_requests SET activated = true, activated_at = $1, activated_domain = $2 WHERE token = $3 RETURNING *", [now, detectedDomain, token]);
  return r.rows[0];
}

// Conversation, messages, usage helpers (as before)
async function getOrCreateConversation(siteId, sessionId) {
  let result = await db.query("SELECT * FROM conversations WHERE site_id = $1 AND session_id = $2", [siteId, sessionId]);
  if (result.rows[0]) return result.rows[0];
  const insert = await db.query("INSERT INTO conversations (site_id, session_id) VALUES ($1, $2) RETURNING *", [siteId, sessionId]);
  return insert.rows[0];
}

async function getOrCreateUsage(siteId, dateStr) {
  let result = await db.query("SELECT * FROM usage_daily WHERE site_id = $1 AND date = $2", [siteId, dateStr]);
  if (result.rows[0]) return result.rows[0];
  const insert = await db.query("INSERT INTO usage_daily (site_id, date, count) VALUES ($1, $2, 0) RETURNING *", [siteId, dateStr]);
  return insert.rows[0];
}

async function getRagContextForSite(siteId, userText, limit = 5) {
  const text = (userText || "").slice(0, 200);
  if (!text) return "";
  const like = `%${text}%`;
  const result = await db.query("SELECT title, content FROM knowledge_items WHERE site_id = $1 AND (title ILIKE $2 OR content ILIKE $2) ORDER BY created_at DESC LIMIT $3", [siteId, like, limit]);
  if (!result.rows.length) return "";
  return result.rows.map((row, idx) => `### ITEM ${idx+1}: ${row.title}\n${row.content}`).join("\n\n");
}

async function callOpenAIChat(messages, { temperature = 0.6, max_tokens = 500 } = {}) {
  if (!OPENAI_API_KEY) {
    const e = new Error("OPENAI_API_KEY not set");
    e.code = "no_openai_key";
    throw e;
  }
  const resp = await axios.post("https://api.openai.com/v1/chat/completions", { model: "gpt-4o-mini", messages, temperature, max_tokens }, { timeout: 20000, headers: { "Content-Type": "application/json", Authorization: `Bearer ${OPENAI_API_KEY}` } });
  const reply = resp?.data?.choices?.[0]?.message?.content?.trim() || resp?.data?.choices?.[0]?.text || "";
  return reply;
}

// ---------- Helpers: send confirmation email ----------
async function sendDemoConfirmationEmail(demoReq, req) {
  if (!mailTransporter) {
    console.warn("Email transporter not available; cannot send confirmation.");
    return false;
  }
  const protocol = req.headers["x-forwarded-proto"] || req.protocol || "https";
  const apiHost = req.headers.host || req.hostname;
  const confirmUrl = `${protocol}://${apiHost}/site/confirm-email?token=${encodeURIComponent(demoReq.email_confirm_token)}`;
  const subject = "Confirm your demo request";
  const html = `<p>Thanks for requesting a demo. Click the link below to confirm your email and enable activation:</p>
                <p><a href="${confirmUrl}">${confirmUrl}</a></p>
                <p>If you didn't request this, ignore this email.</p>`;
  try {
    await mailTransporter.sendMail({ from: EMAIL_FROM, to: demoReq.email, subject, html });
    return true;
  } catch (e) {
    console.error("Failed to send confirmation email:", e && e.message ? e.message : e);
    return false;
  }
}

// ---------- reCAPTCHA verify ----------
async function verifyRecaptcha(token, remoteip) {
  if (!RECAPTCHA_SECRET) return true;
  try {
    const r = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, { params: { secret: RECAPTCHA_SECRET, response: token, remoteip } });
    return r.data && r.data.success;
  } catch (e) {
    console.warn("reCAPTCHA verify failed:", e && e.message ? e.message : e);
    return false;
  }
}

// ---------- Demo request endpoint (with optional recaptcha & email confirm) ----------
app.post("/site/request-demo", limiter, async (req, res) => {
  try {
    const email = (req.body?.email || "").toString().trim();
    const requestedDomain = (req.body?.requestedDomain || "").toString().trim() || null;
    const plan = (req.body?.plan || "basic").toString();
    const recaptchaToken = (req.body?.recaptchaToken || "").toString();

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ ok: false, error: "invalid_email" });

    if (RECAPTCHA_SECRET) {
      const ok = await verifyRecaptcha(recaptchaToken, req.ip);
      if (!ok) return res.status(400).json({ ok: false, error: "recaptcha_failed" });
    }

    const dr = await createDemoRequest(email, requestedDomain, plan);

    // Send confirmation email if SMTP enabled
    let emailSent = false;
    if (mailTransporter) {
      emailSent = await sendDemoConfirmationEmail(dr, req);
    }

    const protocol = req.headers["x-forwarded-proto"] || req.protocol || "https";
    const apiHost = req.headers.host || req.hostname;
    const apiBase = `${protocol}://${apiHost}`;
    const token = dr.token;

    const embedSnippet = `<script>!function(){fetch("${apiBase}/site/activate",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:"${token}"})}).then(r=>r.json()).then(j=>console.log("mascot activation",j)).catch(e=>console.warn("mascot activate err",e))}();</script>`;

    return res.json({ ok: true, token, embedSnippet, email_confirmation_sent: !!emailSent, message: emailSent ? "Confirmation email sent — click the link to confirm before activating embed." : "Demo request created. If you provided a domain it may activate without confirmation." });
  } catch (e) {
    console.error("/site/request-demo error:", e && e.message ? e.message : e);
    return res.status(500).json({ ok: false, error: "server_error", detail: String(e) });
  }
});

// ---------- Email confirmation endpoint ----------
app.get("/site/confirm-email", async (req, res) => {
  try {
    const token = (req.query?.token || "").toString().trim();
    if (!token) return res.status(400).send("Missing token");
    const dr = await getDemoRequestByEmailConfirmToken(token);
    if (!dr) return res.status(404).send("Invalid or expired token");
    await markDemoRequestEmailConfirmed(dr.id);
    return res.send(`<html><body><h3>Email confirmed</h3><p>Your email is confirmed. Now paste the provided embed snippet on your site to activate the demo.</p></body></html>`);
  } catch (e) {
    console.error("/site/confirm-email error:", e && e.message ? e.message : e);
    return res.status(500).send("Server error");
  }
});

// ---------- Activation endpoint ----------
app.post("/site/activate", async (req, res) => {
  try {
    const token = (req.body?.token || "").toString().trim();
    if (!token) return res.status(400).json({ ok: false, error: "missing_token" });

    const dr = await getDemoRequestByToken(token);
    if (!dr) return res.status(404).json({ ok: false, error: "invalid_token" });
    if (dr.activated) return res.status(400).json({ ok: false, error: "already_activated" });

    // determine domain from Origin header or host
    const origin = req.headers.origin || "";
    let detectedDomain = null;
    if (origin) {
      try { detectedDomain = new URL(origin).hostname; } catch {}
    }
    if (!detectedDomain && req.headers.host) detectedDomain = req.headers.host.split(":")[0];
    if (!detectedDomain) return res.status(400).json({ ok: false, error: "no_origin", message: "Cannot determine domain from request." });

    // If SMTP/email confirmation enabled, require email_confirmed true
    if (mailTransporter) {
      const fresh = await db.query("SELECT email_confirmed FROM demo_requests WHERE id = $1", [dr.id]);
      if (!fresh.rows[0] || !fresh.rows[0].email_confirmed) {
        return res.status(403).json({ ok: false, error: "email_not_confirmed", message: "Please confirm your email before activating the demo." });
      }
    } else {
      // warn but allow activation when no email flow
      console.log("ℹ️ Activation proceeding without email confirmation (SMTP not configured).");
    }

    // create site demo row
    const site = await createSiteDemo(detectedDomain, null, dr.plan || "basic", DEMO_DAYS);
    await activateDemoRequest(token, detectedDomain);

    return res.json({ ok: true, site, message: `Demo activated for ${detectedDomain} until ${site.demo_expires}` });
  } catch (e) {
    console.error("/site/activate error:", e && e.message ? e.message : e);
    return res.status(500).json({ ok: false, error: "server_error", detail: String(e) });
  }
});

// ---------- Stripe checkout scaffold (optional) ----------
app.post("/create-checkout-session", async (req, res) => {
  try {
    if (!stripe) return res.status(501).json({ ok: false, error: "stripe_not_configured" });
    const { domain, plan } = req.body || {};
    if (!domain || !plan) return res.status(400).json({ ok: false, error: "missing_domain_or_plan" });

    // Map plan to price ID (you should create these in Stripe). Replace placeholders below with real price IDs.
    const priceMap = {
      basic: process.env.STRIPE_PRICE_BASIC || null,
      pro: process.env.STRIPE_PRICE_PRO || null,
      advanced: process.env.STRIPE_PRICE_ADVANCED || null
    };
    const priceId = priceMap[plan];
    if (!priceId) return res.status(400).json({ ok: false, error: "price_not_configured_for_plan" });

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${req.protocol}://${req.get("host")}/upgrade-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.protocol}://${req.get("host")}/upgrade-cancel`,
      metadata: { domain, plan }
    });
    return res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error("/create-checkout-session error:", e && e.message ? e.message : e);
    return res.status(500).json({ ok: false, error: String(e) });
  }
});

// ---------- Lead capture ----------
app.post("/lead", async (req, res) => {
  try {
    const { site: siteRaw, name, email, message, pageUrl } = req.body || {};
    const domain = (siteRaw || (req.headers.origin ? new URL(req.headers.origin).hostname : null) || req.headers.host || "").toString().split(":")[0];
    if (!domain) return res.status(400).json({ ok: false, error: "missing_site" });
    const site = await getSiteByDomain(domain) || null;
    const siteId = site ? site.id : null;
    const r = await db.query("INSERT INTO leads (site_id, name, email, message, page_url) VALUES ($1,$2,$3,$4,$5) RETURNING *", [siteId, name || null, email || null, message || null, pageUrl || null]);
    try { if (site && site.webhook_url) axios.post(site.webhook_url, { type: "lead", lead: r.rows[0] }).catch(()=>{}); } catch(e){}
    return res.json({ ok: true, lead: r.rows[0] });
  } catch (e) {
    console.error("/lead error:", e && e.message ? e.message : e);
    return res.status(500).json({ ok: false, error: "server_error", detail: String(e) });
  }
});

// ---------- Chat endpoint (demo limit enforcement) ----------
app.post("/chat", async (req, res) => {
  try {
    const userMessage = (req.body?.message || req.body?.text || "").toString().trim();
    if (!userMessage) return res.status(400).json({ error: "missing_text", message: "Missing 'message' or 'text' in body." });
    if (!OPENAI_API_KEY) return res.status(500).json({ reply: "⚠️ Server not configured with OPENAI_API_KEY." });

    const pageUrl = (req.body?.pageUrl || "").toString();
    const siteRaw = (req.body?.site || "").toString().trim();
    const contextRaw = (req.body?.context || "").toString();
    const sessionIdRaw = (req.body?.sessionId || "").toString().trim();
    const originHeader = req.headers.origin || "";

    let siteDomain = siteRaw;
    if (!siteDomain && originHeader) { try { siteDomain = new URL(originHeader).hostname; } catch {} }
    if (!siteDomain && req.headers.host) siteDomain = req.headers.host.split(":")[0];
    if (!siteDomain) return res.status(400).json({ error: "unknown_site", message: "Site (domain) not provided. Please send 'site' in body or ensure Origin header is set." });

    let site = await getSiteByDomain(siteDomain);
    if (!site) return res.status(403).json({ error: "unknown_site", message: "This site is not registered. Ask site owner to enable demo." });

    // demo lifetime and message limits
    if (site.status === "demo") {
      if (site.demo_expires) {
        const exp = new Date(site.demo_expires);
        if (isNaN(exp.getTime()) || exp.getTime() < Date.now()) return res.status(403).json({ error: "demo_expired", message: "Demo expired. Please upgrade." });
      }
      const limit = site.demo_message_limit || 0;
      const used = site.demo_message_used || 0;
      if (limit > 0 && used >= limit) {
        const upgradeUrl = `https://your-payments.example.com/checkout?domain=${encodeURIComponent(site.domain)}&plan=${encodeURIComponent(site.plan)}`;
        return res.status(402).json({ error: "demo_limit_reached", message: "Demo messages exhausted. Upgrade to continue.", upgrade: { url: upgradeUrl } });
      }
    }

    const planConf = PLAN_CONFIG[site.plan] || PLAN_CONFIG.basic;
    const today = new Date().toISOString().slice(0, 10);
    const usage = await getOrCreateUsage(site.id, today);
    const effectiveQuota = site.daily_quota || planConf.dailyQuota;
    if (effectiveQuota && usage.count >= effectiveQuota) return res.status(429).json({ error: "daily_limit_reached", message: "Daily chat limit reached." });

    const sessionId = sessionIdRaw || `anon-${Date.now()}`;
    const conversation = await getOrCreateConversation(site.id, sessionId);

    try { await db.query("INSERT INTO messages (conversation_id, role, text, page_url) VALUES ($1,$2,$3,$4)", [conversation.id, "user", userMessage, pageUrl || null]); } catch (e) { console.warn("Failed to log user message:", e && e.message ? e.message : e); }

    const contextText = contextRaw.trim().slice(0, 3000) || "No specific page context was provided.";
    let extraRagContext = "";
    if ((planConf.features && planConf.features.fullRag) || site.plan === "pro" || site.plan === "advanced") {
      try { extraRagContext = await getRagContextForSite(site.id, userMessage); } catch (e) { console.warn("RAG context retrieval failed:", e && e.message ? e.message : e); extraRagContext = ""; }
    }

    const baseSystemPrompt =
      site.plan === "advanced" ? "You are an advanced website assistant. Use website content and knowledge base. Act like a smart sales + support agent, but stay concise and clear." :
      site.plan === "pro" ? "You are a website assistant with access to a knowledge base. Use it to answer accurately and clearly." :
      "You are a simple helpful assistant for this website. Be concise and friendly.";

    const systemContext = "You are embedded on a website as a chat widget. Use the provided CONTEXT from the current page when it is relevant. If the context is not helpful, fall back to general knowledge but keep it relevant to this business.";
    const contextPrompt = ["CONTEXT FROM WEBSITE / APP:", `Site: ${siteDomain}`, `Page URL: ${pageUrl || "unknown"}`, "---", contextText, extraRagContext ? "\nADDITIONAL SITE KNOWLEDGE:\n" + extraRagContext : ""].join("\n");

    const messages = [
      { role: "system", content: baseSystemPrompt },
      { role: "system", content: systemContext },
      { role: "system", content: contextPrompt },
      { role: "user", content: userMessage }
    ];

    let reply;
    try { reply = await callOpenAIChat(messages, { temperature: 0.6, max_tokens: 500 }); } catch (err) { const status = err?.response?.status || 502; const friendly = "⚠️ I’m having trouble reaching the AI service. Please try again."; console.error("OpenAI /chat error:", err?.response?.data || err.message || err); return res.status(status).json({ reply: friendly }); }

    try {
      await db.query("BEGIN");
      await db.query("INSERT INTO messages (conversation_id, role, text, page_url) VALUES ($1,$2,$3,$4)", [conversation.id, "assistant", reply, pageUrl || null]);
      await db.query("UPDATE usage_daily SET count = count + 1 WHERE site_id = $1 AND date = $2", [site.id, today]);
      if (site.status === "demo") {
        await db.query("UPDATE sites SET demo_message_used = COALESCE(demo_message_used,0) + 1 WHERE id = $1", [site.id]);
      }
      await db.query("COMMIT");
    } catch (e) {
      try { await db.query("ROLLBACK"); } catch(_) {}
      console.warn("Failed to persist assistant message / counters:", e && e.message ? e.message : e);
    }

    // compute remaining
    let remaining = null;
    if (site.status === "demo") {
      const usedR = await db.query("SELECT demo_message_used, demo_message_limit FROM sites WHERE id = $1", [site.id]);
      const u = usedR.rows[0] || {};
      remaining = (u.demo_message_limit || 0) - (u.demo_message_used || 0);
    } else {
      let newCount = usage.count + 1;
      try {
        const newUsage = await db.query("SELECT count FROM usage_daily WHERE site_id = $1 AND date = $2", [site.id, today]);
        newCount = newUsage.rows[0]?.count ?? newCount;
      } catch (e) {}
      remaining = Math.max((site.daily_quota || PLAN_CONFIG[site.plan]?.dailyQuota || 0) - newCount, 0);
    }

    return res.json({ reply, remaining, plan: site.plan, status: site.status });
  } catch (err) {
    console.error("Unhandled /chat error:", err && err.message ? err.message : err);
    return res.status(500).json({ reply: "⚠️ Server error. Please try again later." });
  }
});

// ---------- Admin & debug ----------
app.get("/admin/sites", async (_req, res) => {
  try {
    const r = await db.query("SELECT id,name,domain,plan,status,demo_expires,demo_message_limit,demo_message_used FROM sites ORDER BY created_at DESC LIMIT 200");
    return res.json({ ok: true, sites: r.rows });
  } catch (e) { console.error("/admin/sites error:", e && e.message ? e.message : e); return res.status(500).json({ ok: false, error: String(e) }); }
});

app.get("/admin/demo-requests", async (_req, res) => {
  try {
    const r = await db.query("SELECT id,email,requested_domain,plan,created_at,activated,email_confirmed FROM demo_requests ORDER BY created_at DESC LIMIT 200");
    return res.json({ ok: true, requests: r.rows });
  } catch (e) { console.error("/admin/demo-requests error:", e && e.message ? e.message : e); return res.status(500).json({ ok: false, error: String(e) }); }
});

// ---------- Uploads ----------
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
app.use("/uploads", express.static(UPLOAD_DIR));
app.post("/mascot/upload", upload.single("mascot"), async (req, res) => {
  try { if (!req.file) return res.status(400).json({ success: false, error: "No file uploaded. Field name 'mascot'." });
    const safeName = `${Date.now()}_${(req.file.originalname || "mascot").replace(/[^\w.-]/g, "_")}`;
    fs.writeFileSync(path.join(UPLOAD_DIR, safeName), req.file.buffer);
    return res.json({ success: true, url: `/uploads/${safeName}` });
  } catch (e) { console.error("Upload error:", e && e.message ? e.message : e); return res.status(500).json({ success: false, error: "Upload failed." }); }
});

// ---------- Health ----------
app.get("/", (_req, res) => res.status(200).send("OK"));
app.get("/health", (_req, res) => res.json({ ok: true, service: "mascot-backend", time: new Date().toISOString() }));
app.get("/health-db", async (_req, res) => { try { const r = await db.query("SELECT NOW()"); res.json({ ok: true, time: r.rows[0].now }); } catch (err) { console.error("DB health error:", err && err.message ? err.message : err); res.status(500).json({ ok: false, error: String(err) }); } });
app.get("/openai/ping", async (_req, res) => { try { if (!OPENAI_API_KEY) return res.status(500).json({ ok: false, detail: "OPENAI_API_KEY not set" }); const r = await axios.get("https://api.openai.com/v1/models", { headers: { Authorization: `Bearer ${OPENAI_API_KEY}` }, timeout: 10000 }); res.json({ ok: true, count: r.data?.data?.length || 0 }); } catch (e) { const status = e?.response?.status || 500; const detail = e?.response?.data || e.message; res.status(status).json({ ok: false, detail }); } });

// ---------- Start ----------
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT} (mascot-backend). OpenAI key ${OPENAI_API_KEY ? "present" : "MISSING"}`));
