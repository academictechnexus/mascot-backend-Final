const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const dotenv = require("dotenv");
const OpenAI = require("openai");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// --- OpenAI Setup ---
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// --- Middleware ---
app.use(cors({
  origin: [
    "https://yourfrontenddomain.com",   // replace with your Vercel custom domain
    "https://www.yourfrontenddomain.com"
  ],
  methods: ["GET", "POST"],
}));
app.use(express.json());
app.use(helmet());
app.use(morgan("dev"));

// Rate limiting (100 requests / 15 min per IP)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// --- Extra debug logging ---
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  if (req.body) console.log("Body:", req.body);
  next();
});

// --- Shopify stubs (replace later with real Shopify API) ---
async function getProducts(query) {
  return [
    { name: "Demo Shoe", price: "$49.99" },
    { name: "Demo Sneaker", price: "$39.99" }
  ];
}
async function trackOrder(orderId) {
  return `Order ${orderId} is being processed.`;
}

// --- /api/chat ---
app.post("/api/chat", async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: "Message is required" });

    let botReply;

    if (message.toLowerCase().includes("order")) {
      botReply = await trackOrder("12345");
    } else if (message.toLowerCase().includes("shoe") || message.toLowerCase().includes("sneaker")) {
      const products = await getProducts(message);
      botReply = "Here are some products:\n" + products.map(p => `${p.name} - ${p.price}`).join("\n");
    } else {
      // General GPT reply
      const completion = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: message }],
      });
      botReply = completion.choices[0].message.content;
    }

    res.json({ text: botReply });
  } catch (err) {
    console.error("Error in /api/chat:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// --- /api/tts ---
app.post("/api/tts", async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: "Text is required" });

    const speech = await openai.audio.speech.create({
      model: "gpt-4o-mini-tts",
      voice: "alloy",
      input: text,
    });

    const buffer = Buffer.from(await speech.arrayBuffer());
    res.setHeader("Content-Type", "audio/mpeg");
    res.send(buffer);
  } catch (err) {
    console.error("Error in /api/tts:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// --- Health check ---
app.get("/", (req, res) => res.send("✅ Shop Assistant API running"));

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
