/**
 * server.js (final replacement)
 * - REST-based OpenAI calls (no SDK) to avoid version mismatch issues
 * - Optional ElevenLabs TTS (returns base64 data URL)
 * - Endpoints used by widget:
 *    POST /api/message  -> { text, ttsUrl }
 *    POST /api/lead     -> { id }
 *    POST /mascot/upload
 *    POST /api/chat     -> legacy
 * - Saves leads to leads.json, chat logs to chatlogs/*.jsonl
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

// ---------- tolerant env resolution ----------
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || process.env.OPENAI_KEY || process.env.OPENAI;
const OPENAI_MODEL = process.env.OPENAI_MODEL || process.env.OPENAI_MODEL_NAME || "gpt-4o-mini";
const ELEVENLABS_API_KEY = process.env.ELEVENLABS_API_KEY || process.env.ELEVENLABS_KEY || process.env.ELEVENLABS;
const ELEVENLABS_VOICE = process.env.ELEVENLABS_VOICE || process.env.ELEVEN_VOICE || "alloy";
const SLACK_WEBHOOK = process.env.SLACK_WEBHOOK_URL || process.env.SLACK_WEBHOOK || process.env.SLACK_WEBHOOK_URL;
const BASE_URL = process.env.BASE_URL || "";
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS || "";
const MAX_UPLOAD_BYTES = parseInt(process.env.MAX_UPLOAD_BYTES || process.env.UPLOAD_MAX || String(2 * 1024 * 1024), 10);
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || "12", 10);
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || "10000", 10);
const PLACEHOLDER_GLB = process.env.PLACEHOLDER_GLB || "https://models.readyplayer.me/68b5e67fbac430a52ce1260e.glb";

// Node fetch
const fetchFn = global.fetch.bind(global);

// ---------- app setup ----------
const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

// rate limiter
app.use(rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX
}));

// cors
const allowedOriginsList = ALLOWED_ORIGINS.split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOriginsList.length === 0) return callback(null, true);
    if (allowedOriginsList.indexOf(origin) !== -1) return callback(null, true);
    return callback(new Error("CORS error: origin not allowed"));
  },
  credentials: true
}));

// uploads
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safe = Date.now() + "-" + file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, safe);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_BYTES },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) return cb(new Error("Only image files are allowed"));
    cb(null, true);
  }
});
app.use("/uploads", express.static(UPLOAD_DIR, { index: false }));

// ---------- helpers ----------
function getBaseUrl(req) {
  if (BASE_URL) return BASE_URL.replace(/\/$/, "");
  const proto = req.headers["x-forwarded-proto"] || req.protocol;
  const host = req.headers["x-forwarded-host"] || req.get("host");
  return `${proto}://${host}`;
}

function rndId(prefix = "id") {
  return prefix + "_" + Math.random().toString(36).slice(2, 9);
}

// leads persistence
const LEADS_FILE = path.join(__dirname, "leads.json");
function saveLeadToFile(lead) {
  try {
    if (!fs.existsSync(LEADS_FILE)) fs.writeFileSync(LEADS_FILE, "[]", "utf8");
    const raw = fs.readFileSync(LEADS_FILE, "utf8") || "[]";
    const arr = JSON.parse(raw);
    arr.push(lead);
    fs.writeFileSync(LEADS_FILE, JSON.stringify(arr, null, 2), "utf8");
  } catch (e) {
    console.warn("saveLeadToFile failed:", e);
  }
}

// chat log append
function appendChatLog(entry) {
  try {
    const dir = path.join(__dirname, "chatlogs");
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, `${new Date().toISOString().slice(0,10)}.jsonl`);
    fs.appendFileSync(file, JSON.stringify(entry) + "\n", "utf8");
  } catch (e) {
    console.warn("appendChatLog failed:", e);
  }
}

// ---------- OpenAI REST helper ----------
async function callOpenAIChat({ messages, model = OPENAI_MODEL, max_tokens = 800, timeoutMs = 60000 }) {
  if (!OPENAI_API_KEY) throw new Error("OPENAI_API_KEY not configured");
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetchFn("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${OPENAI_API_KEY}`
      },
      body: JSON.stringify({ model, messages, max_tokens }),
      signal: controller.signal
    });
    clearTimeout(id);
    if (!resp.ok) {
      const txt = await resp.text();
      const err = new Error(`OpenAI API error ${resp.status}: ${txt}`);
      err.status = resp.status;
      throw err;
    }
    return await resp.json();
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

// ---------- ElevenLabs TTS helper (optional) ----------
async function callElevenLabsTTS(text) {
  if (!ELEVENLABS_API_KEY) return null;
  try {
    // ElevenLabs endpoint may vary; this is a generic POST flavor.
    const endpoint = `https://api.elevenlabs.io/v1/text-to-speech/${encodeURIComponent(ELEVENLABS_VOICE)}`;
    const r = await fetchFn(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "xi-api-key": ELEVENLABS_API_KEY
      },
      body: JSON.stringify({ text })
    });
    if (!r.ok) {
      const body = await r.text();
      console.warn("ElevenLabs TTS error:", r.status, body);
      return null;
    }
    const buffer = await r.arrayBuffer();
    const base64 = Buffer.from(buffer).toString("base64");
    return `data:audio/mpeg;base64,${base64}`;
  } catch (e) {
    console.warn("callElevenLabsTTS failed:", e);
    return null;
  }
}

// ---------- Routes ----------

// health
app.get("/", (req, res) => res.json({ status: "ok", message: "Shop Assistant API running" }));

// mascot upload
app.post("/mascot/upload", upload.single("mascot"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    const base = getBaseUrl(req);
    const uploaded_image_url = `${base}/uploads/${req.file.filename}`;
    const glb_url = PLACEHOLDER_GLB;
    return res.json({ uploaded_image_url, glb_url, note: "placeholder GLB returned (demo)" });
  } catch (err) {
    console.error("upload error:", err);
    return res.status(500).json({ error: "upload failed" });
  }
});

// legacy /api/chat (kept)
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

// NEW: /api/message for widget
app.post("/api/message", async (req, res) => {
  try {
    const { sessionId, text } = req.body || {};
    if (!text || String(text).trim().length === 0) return res.status(400).json({ error: "No text provided" });

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
    if (!replyText) replyText = `Demo reply: ${String(text).slice(0, 200)}`;

    // TTS
    let ttsUrl = null;
    if (ELEVENLABS_API_KEY) {
      try {
        ttsUrl = await callElevenLabsTTS(replyText);
      } catch (e) {
        console.warn("TTS failed:", e);
        ttsUrl = null;
      }
    }

    // save chat log (non-blocking)
    try {
      appendChatLog({ id: rndId("chat"), sessionId: sessionId || null, text, reply: replyText, created_at: new Date().toISOString() });
    } catch (e) {
      console.warn("could not save chat log:", e);
    }

    return res.json({ text: replyText, ttsUrl });
  } catch (err) {
    console.error("/api/message error:", err);
    return res.status(500).json({ error: "server error" });
  }
});

// NEW: /api/lead
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

    try { saveLeadToFile(lead); } catch (e) { console.warn("persist lead failed:", e); }

    // notify slack if available
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

// final health
app.get("/health", (req, res) => res.json({ status: "ok" }));

// start
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
