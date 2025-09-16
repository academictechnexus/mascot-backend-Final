/**
 * server.js (updated)
 * - Provides /api/message and /api/lead to match the frontend widget
 * - Uses fetch-based OpenAI REST calls (no SDK) to avoid version mismatches
 * - Optional ElevenLabs TTS: returns data:audio/... base64 audio as ttsUrl when available
 * - Simple leads persistence to file + optional Slack notification
 *
 * Environment variables:
 *  OPENAI_API_KEY
 *  OPENAI_MODEL (optional, default: "gpt-4o-mini")
 *  ELEVENLABS_API_KEY (optional)
 *  ELEVENLABS_VOICE (optional, voice id)
 *  SLACK_WEBHOOK_URL (optional)
 *  BASE_URL (optional)
 *  ALLOWED_ORIGINS (optional, comma-separated)
 */

const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const dotenv = require("dotenv");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Built-in fetch in Node 18+; use globally
const fetchFn = global.fetch.bind(global);
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini";
const ELEVENLABS_API_KEY = process.env.ELEVENLABS_API_KEY;
const ELEVENLABS_VOICE = process.env.ELEVENLABS_VOICE || "alloy";
const SLACK_WEBHOOK = process.env.SLACK_WEBHOOK_URL || process.env.SLACK_WEBHOOK;
const PLACEHOLDER_GLB = process.env.PLACEHOLDER_GLB || "https://models.readyplayer.me/68b5e67fbac430a52ce1260e.glb";

// ---- Basic middlewares ----
app.use(helmet());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

// Rate limiter
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "10000", 10),
  max: parseInt(process.env.RATE_LIMIT_MAX || "12", 10),
});
app.use(limiter);

// CORS
const allowedOriginsEnv = process.env.ALLOWED_ORIGINS || "";
const allowedOrigins = allowedOriginsEnv.split(",").map(s => s.trim()).filter(Boolean);
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.length === 0) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) return callback(null, true);
    return callback(new Error("CORS error: origin not allowed"));
  },
  credentials: true,
};
app.use(cors(corsOptions));

// Uploads
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safe = Date.now() + "-" + file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, safe);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: parseInt(process.env.MAX_UPLOAD_BYTES || (2 * 1024 * 1024), 10) },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) return cb(new Error("Only image files are allowed"));
    cb(null, true);
  },
});

app.use("/uploads", express.static(UPLOAD_DIR, { index: false }));

// ---------------- utilities ----------------
function getBaseUrl(req) {
  if (process.env.BASE_URL) return process.env.BASE_URL.replace(/\/$/, "");
  const proto = req.headers["x-forwarded-proto"] || req.protocol;
  const host = req.headers["x-forwarded-host"] || req.get("host");
  return `${proto}://${host}`;
}

function rndId(prefix = "id") {
  return prefix + "_" + Math.random().toString(36).slice(2, 9);
}

// Simple append-to-file leads store (not heavy-duty, but okay for demo)
const LEADS_FILE = path.join(__dirname, "leads.json");
function saveLeadToFile(lead) {
  const exists = fs.existsSync(LEADS_FILE);
  if (!exists) fs.writeFileSync(LEADS_FILE, "[]");
  const raw = fs.readFileSync(LEADS_FILE, "utf8");
  let arr = [];
  try { arr = JSON.parse(raw || "[]"); } catch (e) { arr = []; }
  arr.push(lead);
  fs.writeFileSync(LEADS_FILE, JSON.stringify(arr, null, 2));
}

// ---------- OpenAI helper (fetch-based) ----------
async function callOpenAIChat({ messages, model = OPENAI_MODEL, max_tokens = 800, timeoutMs = 60000 }) {
  if (!OPENAI_API_KEY) throw new Error("OPENAI_API_KEY not configured");
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetchFn("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${OPENAI_API_KEY}`,
      },
      body: JSON.stringify({
        model,
        messages,
        max_tokens,
      }),
      signal: controller.signal,
    });
    clearTimeout(id);
    if (!resp.ok) {
      const txt = await resp.text();
      const err = new Error(`OpenAI API error ${resp.status}: ${txt}`);
      err.status = resp.status;
      throw err;
    }
    const data = await resp.json();
    return data;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

// ---------- ElevenLabs TTS helper (optional) ----------
async function callElevenLabsTTS(text) {
  if (!ELEVENLABS_API_KEY) return null;
  try {
    // NOTE: ElevenLabs API may have different endpoints/params depending on your account.
    // This is a generic approach: POST text, receive audio bytes.
    // Adjust the endpoint/voice id as per your ElevenLabs account docs.
    const endpoint = `https://api.elevenlabs.io/v1/text-to-speech/${encodeURIComponent(ELEVENLABS_VOICE)}`;
    const resp = await fetchFn(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "xi-api-key": ELEVENLABS_API_KEY,
      },
      body: JSON.stringify({ text }),
    });
    if (!resp.ok) {
      const body = await resp.text();
      console.warn("ElevenLabs TTS error:", resp.status, body);
      return null;
    }
    const arrayBuffer = await resp.arrayBuffer();
    const base64 = Buffer.from(arrayBuffer).toString("base64");
    // Return data URL (audio/mpeg is a safe generic type; some APIs return wav/ogg)
    return `data:audio/mpeg;base64,${base64}`;
  } catch (err) {
    console.warn("ElevenLabs TTS call failed:", err);
    return null;
  }
}

// ================ Routes ==================

// Health
app.get("/", (req, res) => res.json({ status: "ok", message: "Shop Assistant API running" }));

// mascot upload (kept from original)
app.post("/mascot/upload", upload.single("mascot"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    const base = getBaseUrl(req);
    const uploaded_image_url = `${base}/uploads/${req.file.filename}`;
    const glb_url = PLACEHOLDER_GLB;
    return res.json({
      uploaded_image_url,
      glb_url,
      note: "demo: placeholder GLB returned. Replace with your 2D->3D generator result",
    });
  } catch (err) {
    console.error("upload error:", err);
    return res.status(500).json({ error: "upload failed" });
  }
});

// Legacy /api/chat kept for backward compatibility — returns same shape as demo earlier
app.post("/api/chat", async (req, res) => {
  try {
    const { message } = req.body || {};
    if (!message || String(message).trim().length === 0) return res.status(400).json({ error: "No message provided" });

    const txt = String(message).toLowerCase();
    let action = "talk";
    if (txt.includes("dance")) action = "dance";
    else if (txt.includes("walk")) action = "walk";
    else if (txt.includes("wave")) action = "wave";

    if (OPENAI_API_KEY) {
      try {
        const messages = [
          { role: "system", content: "You are a friendly shop assistant for an ecommerce store. Answer helpfully and concisely." },
          { role: "user", content: message }
        ];
        const completion = await callOpenAIChat({ messages, model: OPENAI_MODEL, max_tokens: 400 });
        const replyText = completion?.choices?.[0]?.message?.content || completion?.choices?.[0]?.text || "Sorry — could not generate reply.";
        return res.json({ reply: replyText, action });
      } catch (err) {
        console.error("OpenAI error (api/chat):", err);
        // fall through to demo fallback
      }
    }

    // fallback
    let reply = "Demo assistant: " + String(message);
    if (action === "dance") reply = "Let's dance! 💃";
    else if (action === "walk") reply = "Taking a short walk... 🚶";
    else if (action === "wave") reply = "Waving hello! 👋";
    else reply = "Thanks! I heard you — this is a demo reply.";
    return res.json({ reply, action });
  } catch (err) {
    console.error("/api/chat error:", err);
    return res.status(500).json({ error: "server error" });
  }
});

// NEW: /api/message used by frontend widget I provided
// Accepts: { sessionId, text }  -> returns { text, ttsUrl }
app.post("/api/message", async (req, res) => {
  try {
    const { sessionId, text } = req.body || {};
    if (!text || String(text).trim().length === 0) return res.status(400).json({ error: "No text provided" });

    // Build messages for OpenAI
    const messages = [
      { role: "system", content: "You are a helpful Shopify app developer assistant. Keep replies short and actionable." },
      { role: "user", content: String(text) }
    ];

    let replyText = null;
    if (OPENAI_API_KEY) {
      try {
        const completion = await callOpenAIChat({ messages, model: OPENAI_MODEL, max_tokens: 500 });
        replyText = completion?.choices?.[0]?.message?.content || completion?.choices?.[0]?.text || null;
      } catch (err) {
        console.error("OpenAI call failed (api/message):", err);
        replyText = null;
      }
    }

    if (!replyText) {
      // demo fallback
      replyText = `Demo reply: ${String(text).slice(0, 200)}`;
    }

    // Optionally generate TTS using ElevenLabs (returns data:audio/... base64)
    let ttsUrl = null;
    if (ELEVENLABS_API_KEY) {
      try {
        ttsUrl = await callElevenLabsTTS(replyText);
      } catch (err) {
        console.warn("TTS generation failed:", err);
        ttsUrl = null;
      }
    }

    // Save basic chat log (non-blocking)
    try {
      const chatLogDir = path.join(__dirname, "chatlogs");
      if (!fs.existsSync(chatLogDir)) fs.mkdirSync(chatLogDir, { recursive: true });
      const file = path.join(chatLogDir, `${new Date().toISOString().slice(0,10)}.jsonl`);
      const entry = { id: rndId("chat"), sessionId: sessionId || null, text: text, reply: replyText, created_at: new Date().toISOString() };
      fs.appendFileSync(file, JSON.stringify(entry) + "\n");
    } catch (e) {
      console.warn("could not save chat log:", e);
    }

    return res.json({ text: replyText, ttsUrl });
  } catch (err) {
    console.error("/api/message error:", err);
    return res.status(500).json({ error: "server error" });
  }
});

// NEW: /api/lead used by frontend widget I provided
// Accepts: { name, email, need, storeUrl, message }
// Returns: { id }
app.post("/api/lead", async (req, res) => {
  try {
    const { name, email, need, storeUrl, message } = req.body || {};
    if (!name || !email) return res.status(400).json({ error: "name and email required" });

    const lead = {
      id: rndId("lead"),
      name: String(name),
      email: String(email),
      need: String(need || ""),
      storeUrl: String(storeUrl || ""),
      message: String(message || ""),
      created_at: new Date().toISOString()
    };

    // persist lead
    try {
      saveLeadToFile(lead);
    } catch (e) {
      console.warn("couldn't persist lead locally:", e);
    }

    // notify Slack if configured (best-effort)
    if (SLACK_WEBHOOK) {
      try {
        await fetchFn(SLACK_WEBHOOK, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: `New lead: ${lead.name} <${lead.email}> - ${lead.need || 'no-need'} - ${lead.storeUrl || 'no-store'}` })
        });
      } catch (e) {
        console.warn("slack notify failed:", e);
      }
    }

    return res.json({ id: lead.id });
  } catch (err) {
    console.error("/api/lead error:", err);
    return res.status(500).json({ error: "server error" });
  }
});

// Health
app.get("/health", (req, res) => res.json({ status: "ok" }));

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
