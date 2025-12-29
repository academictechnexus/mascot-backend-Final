// workflows/escalation.workflow.js
// SMB-style escalation workflow (Zendesk-inspired, simplified)
//
// Responsibilities:
// - Decide when escalation is needed
// - Generate ticket/reference ID
// - Persist escalation record
// - Notify business owner
// - Return customer acknowledgment
//
// DOES NOT:
// - Manage ticket lifecycle
// - Assign agents
// - Track SLAs

const crypto = require("crypto");

// Lazy imports to avoid breaking server on first load
let db = null;
try {
  db = require("../services/db.service"); // optional future abstraction
} catch (_) {
  db = null;
}

let notificationService = null;
try {
  notificationService = require("../services/notification.service");
} catch (_) {
  notificationService = null;
}

// -------------------------------
// Config (safe defaults)
// -------------------------------
const ESCALATION_INTENTS = [
  "refund",
  "complaint",
  "cancel",
  "angry",
  "legal"
];

const CONFIDENCE_THRESHOLD = 0.6;

// -------------------------------
// Utilities (local to this file)
// -------------------------------
function generateTicketId() {
  const ts = Date.now().toString(36).toUpperCase();
  const rand = crypto.randomBytes(3).toString("hex").toUpperCase();
  return `TKT-${ts}-${rand}`;
}

function normalizeText(t = "") {
  return t.toString().toLowerCase();
}

function detectIntent(text = "") {
  const t = normalizeText(text);
  for (const intent of ESCALATION_INTENTS) {
    if (t.includes(intent)) return intent;
  }
  return "general";
}

function shouldEscalate({ confidence, intent }) {
  if (confidence !== null && confidence < CONFIDENCE_THRESHOLD) return true;
  if (ESCALATION_INTENTS.includes(intent)) return true;
  return false;
}

function summarizeConversation(messages = []) {
  if (!messages.length) return "Customer inquiry (summary unavailable).";
  const lastUser = [...messages].reverse().find(m => m.role === "user");
  return lastUser
    ? lastUser.text.slice(0, 240)
    : "Customer inquiry.";
}

// -------------------------------
// Persistence helpers
// -------------------------------
async function ensureEscalationTable(pool) {
  const sql = `
    CREATE TABLE IF NOT EXISTS escalations (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      site_id UUID,
      ticket_id TEXT NOT NULL UNIQUE,
      channel TEXT,
      customer_contact TEXT,
      intent TEXT,
      confidence NUMERIC,
      summary TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `;
  await pool.query(sql);
}

async function saveEscalation(pool, data) {
  const {
    siteId,
    ticketId,
    channel,
    customerContact,
    intent,
    confidence,
    summary
  } = data;

  const sql = `
    INSERT INTO escalations
      (site_id, ticket_id, channel, customer_contact, intent, confidence, summary)
    VALUES
      ($1,$2,$3,$4,$5,$6,$7)
    RETURNING *;
  `;
  const r = await pool.query(sql, [
    siteId,
    ticketId,
    channel,
    customerContact,
    intent,
    confidence,
    summary
  ]);
  return r.rows[0];
}

// -------------------------------
// Main workflow
// -------------------------------
async function handleEscalation({
  pool,                // pg Pool (pass from server.js later)
  site,                // site row
  channel,             // web | whatsapp | etc
  customerContact,     // email / phone / anon
  messages,            // conversation messages
  aiConfidence = null, // number | null
  forced = false       // override
}) {
  if (!pool) {
    throw new Error("DB pool not provided to escalation workflow");
  }

  await ensureEscalationTable(pool);

  const lastUserMessage = [...messages].reverse().find(m => m.role === "user");
  const userText = lastUserMessage ? lastUserMessage.text : "";

  const intent = detectIntent(userText);
  const escalate = forced || shouldEscalate({
    confidence: aiConfidence,
    intent
  });

  if (!escalate) {
    return {
      escalated: false
    };
  }

  const ticketId = generateTicketId();
  const summary = summarizeConversation(messages);

  const record = await saveEscalation(pool, {
    siteId: site.id,
    ticketId,
    channel,
    customerContact,
    intent,
    confidence: aiConfidence,
    summary
  });

  // Notify business owner (best effort)
  try {
    if (notificationService) {
      await notificationService.notifyOwner({
        site,
        ticketId,
        channel,
        summary,
        customerContact
      });
    }
  } catch (e) {
    console.warn("Owner notification failed:", e.message || e);
  }

  return {
    escalated: true,
    ticketId,
    messageToCustomer:
      `Thanks for reaching out 🙏\n\n` +
      `We’ve shared your request with our team.\n` +
      `**Reference ID:** ${ticketId}\n\n` +
      `You’ll hear back shortly.`
  };
}

// -------------------------------
// Exports
// -------------------------------
module.exports = {
  handleEscalation
};
