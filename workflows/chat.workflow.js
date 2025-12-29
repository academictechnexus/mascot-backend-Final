// workflows/chat.workflow.js
// Central chat brain (Zendesk-style, SMB-optimized)
//
// Responsibilities:
// - Orchestrate AI response
// - Estimate confidence
// - Trigger escalation when needed
// - Stay channel-aware
//
// Does NOT:
// - Replace existing /chat endpoint yet
// - Handle HTTP directly

const escalationWorkflow = require("./escalation.workflow");

// -------------------------------
// Confidence estimation (simple & fast)
// -------------------------------
function estimateConfidence(aiReply = "", contextUsed = false) {
  if (!aiReply) return 0.2;

  let score = 0.6;

  if (aiReply.length > 120) score += 0.1;
  if (contextUsed) score += 0.1;
  if (aiReply.includes("I am not sure")) score -= 0.2;
  if (aiReply.includes("please contact")) score -= 0.1;

  return Math.max(0, Math.min(1, score));
}

// -------------------------------
// Message normalization
// -------------------------------
function normalizeMessage(input) {
  return (input || "").toString().trim();
}

// -------------------------------
// Main handler
// -------------------------------
async function handleChat({
  pool,             // pg Pool
  site,             // site row
  channel = "web",  // web | whatsapp | etc
  sessionId,
  userMessage,
  aiReply,          // AI response text (from existing logic)
  conversationLog,  // [{ role, text }]
  contextUsed = false,
  customerContact = null
}) {
  if (!pool) throw new Error("DB pool required");
  if (!site || !site.id) throw new Error("Valid site required");

  const cleanUserMsg = normalizeMessage(userMessage);
  const cleanAiReply = normalizeMessage(aiReply);

  // 1️⃣ Estimate confidence
  const confidence = estimateConfidence(cleanAiReply, contextUsed);

  // 2️⃣ Attempt escalation
  let escalationResult = null;

  try {
    escalationResult = await escalationWorkflow.handleEscalation({
      pool,
      site,
      channel,
      customerContact,
      messages: conversationLog,
      aiConfidence: confidence
    });
  } catch (e) {
    console.warn("Escalation workflow failed:", e.message || e);
    escalationResult = { escalated: false };
  }

  // 3️⃣ Final response to customer
  if (escalationResult.escalated) {
    return {
      reply: escalationResult.messageToCustomer,
      escalated: true,
      ticketId: escalationResult.ticketId,
      confidence
    };
  }

  return {
    reply: cleanAiReply,
    escalated: false,
    confidence
  };
}

// -------------------------------
// Export
// -------------------------------
module.exports = {
  handleChat
};
