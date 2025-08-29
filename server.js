// server.js
// Fresh backend: Health, OpenAI chat, mascot upload (local), safe defaults.

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const axios = require("axios");
const morgan = require("morgan");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const app = express();

// ---------- Config ----------
const PORT = process.env.PORT || 8080;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";

// ---------- Middlewares ----------
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);
app.use(express.json({ limit: "1mb" }));

// TEMP: allow all origins (works everywhere). Tighten later with an allowlist.
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Logging (no bodies)
morgan.token("reqid", () => Math.random().toString(36).slice(2, 9));
app.use(morgan(":reqid :method :url :status - :response-time ms", { skip: r => r.path === "/health" }));

// Rate limit just the AI & upload endpoints
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "10000", 10),
  max: parseInt(process.env.RATE_LIMIT_MAX || "8", 10),
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/chat", limiter);
app.use("/mascot/upload", limiter);

// ---------- Health ----------
app.get("/", (_req, res) => res.status(200).send("OK"));
app.get("/health", (_req, res) =>
  res.json({ ok: true, service: "mascot-backend", time: new Date().toISOString() })
);

// ---------- Diagnostics ----------
app.get("/openai/ping", async (_req, res) => {
  try {
    if (!OPENAI_API_KEY) return res.status(500).json({ ok: false, detail: "OPENAI_API_KEY not set" });
    const r = await axios.get("https://api.openai.com/v1/models", {
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}` },
      timeout: 10000,
    });
    res.json({ ok: true, count: r.data?.data?.length || 0 });
  } catch (e) {
    const status = e?.response?.status || 500;
    const detail = e?.response?.data || e.message;
    res.status(status).json({ ok: false, detail });
  }
});

// Helpful message if someone GETs /chat in a browser
app.get("/chat", (_req, res) =>
  res.status(405).json({ error: "Use POST /chat", example: { message: "Hello" } })
);

// ---------- Chat (OpenAI) ----------
const SYSTEM_PROMPT =
  "You are Academic Technexus's helpful assistant. Be concise, friendly, and safe.";

app.post("/chat", async (req, res) => {
  try {
    const userMessage = (req.body?.message || "").toString().trim();
    if (!userMessage) return res.status(400).json({ error: "Missing 'message' in body." });

    if (!OPENAI_API_KEY) {
      return res.status(500).json({ reply: "⚠️ Server not configured with OPENAI_API_KEY." });
    }

    const ai = await axios.post(
      "https://api.openai.com/v1/chat/completions",
      {
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: userMessage },
        ],
        temperature: 0.6,
        max_tokens: 500,
      },
      {
        timeout: 20000,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${OPENAI_API_KEY}`,
        },
      }
    );

    const reply = ai?.data?.choices?.[0]?.message?.content?.trim() || "Sorry, I couldn’t generate a response.";
    res.json({ reply });
  } catch (err) {
    const status = err?.response?.status || 502;
    const code = err?.response?.data?.error?.code;
    const friendly =
      code === "insufficient_quota"
        ? "⚠️ Demo usage limit reached. Please try again later."
        : "⚠️ I’m having trouble reaching the AI service. Please try again.";
    console.error("OpenAI /chat error:", err?.response?.data || err.message);
    res.status(status).json({ reply: friendly });
  }
});

// ---------- Mascot Upload (local storage) ----------
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } }); // 5MB
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
app.use("/uploads", express.static(UPLOAD_DIR));

app.post("/mascot/upload", upload.single("mascot"), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: "No file uploaded. Field name 'mascot'." });
    const safeName = `${Date.now()}_${(req.file.originalname || "mascot").replace(/[^\w.-]/g, "_")}`;
    fs.writeFileSync(path.join(UPLOAD_DIR, safeName), req.file.buffer);
    return res.json({ success: true, url: `/uploads/${safeName}` });
  } catch (e) {
    console.error("Upload error:", e.message);
    return res.status(500).json({ success: false, error: "Upload failed." });
  }
});

// ---------- Start ----------
app.listen(PORT, () => console.log(`✅ Secure server running on port ${PORT}`));
