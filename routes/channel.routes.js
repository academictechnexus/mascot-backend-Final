// routes/channel.routes.js
// Channel intake routes (Website, WhatsApp, others)
// Thin layer only — no AI or DB logic here

const express = require("express");
const router = express.Router();

let channelWorkflow = null;
try {
  channelWorkflow = require("../workflows/channel.workflow");
} catch (e) {
  // workflow not ready yet — safe fallback
  channelWorkflow = null;
}

/**
 * POST /channels/web
 * Entry point for website widget
 */
router.post("/web", async (req, res) => {
  try {
    if (!channelWorkflow) {
      return res.status(501).json({
        ok: false,
        error: "channel_workflow_not_ready"
      });
    }

    const {
      message,
      sessionId,
      site,
      pageUrl,
      context
    } = req.body || {};

    if (!message) {
      return res.status(400).json({ ok: false, error: "missing_message" });
    }

    const result = await channelWorkflow.handleIncoming({
      channel: "web",
      message,
      sessionId: sessionId || null,
      site: site || null,
      pageUrl: pageUrl || null,
      context: context || null,
      raw: req.body
    });

    return res.json({ ok: true, data: result });
  } catch (e) {
    console.error("channels/web error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

/**
 * POST /channels/whatsapp
 * Entry point for WhatsApp webhook
 */
router.post("/whatsapp", async (req, res) => {
  try {
    if (!channelWorkflow) {
      return res.status(501).json({
        ok: false,
        error: "channel_workflow_not_ready"
      });
    }

    // WhatsApp payloads differ by provider (Twilio / Meta)
    const payload = req.body || {};
    const message =
      payload?.message ||
      payload?.Body ||
      payload?.text ||
      null;

    const from =
      payload?.from ||
      payload?.From ||
      payload?.sender ||
      null;

    if (!message || !from) {
      return res.status(400).json({
        ok: false,
        error: "invalid_whatsapp_payload"
      });
    }

    const result = await channelWorkflow.handleIncoming({
      channel: "whatsapp",
      message,
      sessionId: from, // phone number as session
      site: null,
      pageUrl: null,
      context: null,
      raw: payload
    });

    return res.json({ ok: true, data: result });
  } catch (e) {
    console.error("channels/whatsapp error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

module.exports = router;
