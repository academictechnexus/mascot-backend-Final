// workflows/channel.workflow.js
// Channel intelligence layer (Zendesk-style, SMB-optimized)
//
// Responsibilities:
// - Normalize incoming messages from different channels
// - Resolve site + session identity
// - Call chat.workflow as the single brain
// - Return channel-appropriate response
//
// Does NOT:
// - Handle HTTP
// - Talk directly to OpenAI
// - Persist messages (server.js already does that)

const chatWorkflow = require("./chat.workflow");

// -------------------------------
// Helpers
// -------------------------------
function normalizeText(v) {
  return (v || "").toString().trim();
}

function resolveSessionId({ channel, sessionId, customerContact }) {
  if (sessionId) return sessionId;
  if (customerContact) return `${channel}-${customerContact}`;
  return `${channel}-anon-${Date.now()}`;
}

function extractConversationLog(raw) {
  // Expecting [{ role, text }]
  if (Array.isArray(raw)) return raw;
  return [];
}

// -------------------------------
// Main handler
// -------------------------------
async function handleIncoming({
  pool,
  site,
  channel = "web",
  message,
  sessionId,
  pageUrl,
  context,
  customerContact,
  conversationLog,
  raw
}) {
  if (!pool) throw new Error("DB pool required");
  if (!site || !site.id) throw new Error("Valid site required");
  if (!message) throw new Error("Message is required");

  const cleanMessage = normalizeText(message);

  const finalSessionId = resolveSessionId({
    channel,
    sessionId,
    customerContact
  });

  // Build conversation context (lightweight)
  const convoLog = extractConversationLog(conversationLog);

  // Detect whether context was used (simple heuristic)
  const contextUsed = !!(context && normalizeText(context).length > 20);

  // NOTE:
  // Actual AI call still happens in existing /chat logic.
  // For now, this workflow assumes `aiReply` will be passed
  // when server.js wiring is done.

  // Placeholder for AI reply until wiring
  const aiReply = raw?.aiReply || "Thanks for your message!";

  // Call central chat brain
  const result = await chatWorkflow.handleChat({
    pool,
    site,
    channel,
    sessionId: finalSessionId,
    userMessage: cleanMessage,
    aiReply,
    conversationLog: convoLog,
    contextUsed,
    customerContact
  });

  // Channel-specific response shaping
  if (channel === "whatsapp") {
    return {
      to: customerContact,
      message: result.reply,
      escalated: result.escalated,
      ticketId: result.ticketId || null
    };
  }

  // Default (web, others)
  return {
    reply: result.reply,
    escalated: result.escalated,
    ticketId: result.ticketId || null,
    confidence: result.confidence
  };
}

// -------------------------------
// Export
// -------------------------------
module.exports = {
  handleIncoming
};
