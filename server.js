/**
 * server.js
 * Complete backend for demo frontend:
 * - POST /mascot/upload  -> saves image, returns { uploaded_image_url, glb_url }
 * - POST /api/chat       -> returns { reply, action } (uses OpenAI if OPENAI_API_KEY provided; otherwise demo stub)
 * - GET /                 -> health check
 *
 * Notes:
 * - The GLB returned is a placeholder (Ready Player Me). Replace with your 2D->3D generation pipeline later.
 * - Configure env vars: OPENAI_API_KEY (optional), BASE_URL (required for production), ALLOWED_ORIGINS (optional)
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
let OpenAI;
try { OpenAI = require("openai"); } catch (e) { OpenAI = null; }

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ---- Basic middlewares ----
app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Logging (morgan) - keep enabled in dev; in production you can disable or buffer.
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

// Rate limiter (simple)
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "10000"), // 10s default
  max: parseInt(process.env.RATE_LIMIT_MAX || "12"), // limit each IP
});
app.use(limiter);

// CORS - configure ALLOWED_ORIGINS as comma-separated list in env if you want to lock down
const allowedOriginsEnv = process.env.ALLOWED_ORIGINS || "";
const allowedOrigins = allowedOriginsEnv.split(",").map(s => s.trim()).filter(Boolean);
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (e.g., curl, server-to-server)
    if (!origin) return callback(null, true);
    if (allowedOrigins.length === 0) {
      // no configured allowed origins -> allow all (demo friendly)
      return callback(null, true);
    }
    if (allowedOrigins.indexOf(origin) !== -1) return callback(null, true);
    return callback(new Error("CORS error: origin not allowed"));
  },
  credentials: true,
};
app.use(cors(corsOptions));

// ---- Uploads setup (multer) ----
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    // safe filename: timestamp + sanitized original name
    const safe = Date.now() + "-" + file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, safe);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: parseInt(process.env.MAX_UPLOAD_BYTES || (2 * 1024 * 1024)) }, // default 2MB
  fileFilter: (req, file, cb) => {
    // allow images only
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only image files are allowed"));
    }
    cb(null, true);
  },
});

// serve uploads statically
app.use("/uploads", express.static(UPLOAD_DIR, { index: false }));

// ---- OpenAI client (optional) ----
let openaiClient = null;
if (process.env.OPENAI_API_KEY && OpenAI) {
  openaiClient = new OpenAI.OpenAIApi ? new OpenAI.OpenAIApi({ apiKey: process.env.OPENAI_API_KEY }) : new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  // Note: depending on openai lib version you have installed you may need to adapt client usage.
} else if (process.env.OPENAI_API_KEY && !OpenAI) {
  console.warn("OPENAI_API_KEY set but 'openai' library not installed or failed to load. Chat will use demo responses.");
}

// Placeholder GLB (Ready Player Me sample). Replace with real generated GLB URL after integrating generator.
const PLACEHOLDER_GLB = process.env.PLACEHOLDER_GLB || "https://models.readyplayer.me/68b5e67fbac430a52ce1260e.glb";

// Utility to compute base URL for uploaded files
function getBaseUrl(req) {
  // prefer env BASE_URL if set (useful for production behind proxies)
  if (process.env.BASE_URL) return process.env.BASE_URL.replace(/\/$/, "");
  // otherwise build from request
  const proto = req.headers["x-forwarded-proto"] || req.protocol;
  const host = req.headers["x-forwarded-host"] || req.get("host");
  return `${proto}://${host}`;
}

// ----------------- Routes -----------------

// Health check
app.get("/", (req, res) => res.json({ status: "ok", message: "Shop Assistant API running" }));

// POST /mascot/upload
// Accepts multipart-form with field 'mascot' (image). Returns { uploaded_image_url, glb_url }.
// For demo we return a placeholder glb_url. Replace with your 2D->3D pipeline later.
app.post("/mascot/upload", upload.single("mascot"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }
    const base = getBaseUrl(req);
    const uploaded_image_url = `${base}/uploads/${req.file.filename}`;

    // In a real pipeline: call your 2D->3D generator, store the GLB and return its URL.
    // For demo: return placeholder GLB.
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

// POST /api/chat
// Accepts JSON { message, store_id?, session_id? } and returns { reply, action }.
// If OPENAI_API_KEY set and openai client available, it will call OpenAI ChatCompletion (simple wrapper).
app.post("/api/chat", async (req, res) => {
  try {
    const { message } = req.body || {};
    if (!message || String(message).trim().length === 0) {
      return res.status(400).json({ error: "No message provided" });
    }

    // Demo heuristic: if message includes dance/walk/wave trigger actions faster
    const txt = String(message).toLowerCase();
    let action = null;
    if (txt.includes("dance")) action = "dance";
    else if (txt.includes("walk")) action = "walk";
    else if (txt.includes("wave")) action = "wave";
    else action = "talk";

    // If OpenAI configured, use it to generate reply
    if (openaiClient && process.env.OPENAI_API_KEY) {
      try {
        // Use a simple prompt with a short system instruction and user message.
        // Adjust model and call depending on your openai SDK version. This example uses the REST-style /chat/completions.
        const promptSystem = "You are a friendly shop assistant for an ecommerce store. Answer helpfully and concisely.";
        const userMessage = message;

        // attempt to use chat completions via the openai lib - handle versions gracefully
        let replyText = null;
        if (typeof openaiClient.createChatCompletion === "function") {
          // older openai lib usage
          const completion = await openaiClient.createChatCompletion({
            model: process.env.OPENAI_MODEL || "gpt-4o-mini",
            messages: [
              { role: "system", content: promptSystem },
              { role: "user", content: userMessage },
            ],
            max_tokens: 400,
          });
          if (completion && completion.data && completion.data.choices && completion.data.choices[0]) {
            replyText = completion.data.choices[0].message?.content || completion.data.choices[0].text || String(completion.data.choices[0]);
          }
        } else if (typeof openaiClient.chat === "function") {
          // newer openai client (openai@4+ usage)
          const completion = await openaiClient.chat.completions.create({
            model: process.env.OPENAI_MODEL || "gpt-4o-mini",
            messages: [
              { role: "system", content: promptSystem },
              { role: "user", content: userMessage },
            ],
            max_tokens: 400,
          });
          if (completion && completion.choices && completion.choices[0]) {
            replyText = completion.choices[0].message?.content || completion.choices[0].text;
          }
        } else {
          // fallback: call the REST endpoint using axios if openai lib isn't compatible
          replyText = null;
        }

        if (!replyText) replyText = `Sorry, I couldn't generate a reply right now. (demo fallback)`;

        return res.json({ reply: replyText, action });
      } catch (err) {
        console.error("OpenAI error, falling back to demo reply:", err);
        // fallthrough to demo reply below
      }
    }

    // Demo fallback reply (no OpenAI configured or OpenAI error)
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

// Optional: TTS endpoint (returns audio bytes) - we keep it optional and guarded.
// If you want to enable cloud TTS, implement here and set env variables.
// This example is intentionally minimal and commented out; enable only when you implement TTS.

// app.post('/api/tts', async (req, res) => { ... });

app.get("/health", (req, res) => res.json({ status: "ok" }));

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
