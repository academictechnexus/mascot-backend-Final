// routes/onboarding.routes.js
// Thin HTTP layer for AI onboarding (SMB setup).
// No business logic here.

const express = require("express");
const router = express.Router();

// workflow will be added later
let onboardingWorkflow = null;
try {
  onboardingWorkflow = require("../workflows/onboarding.workflow");
} catch (e) {
  // workflow not created yet – safe fallback
  onboardingWorkflow = null;
}

/**
 * POST /onboarding/start
 * Starts AI onboarding for a site
 */
router.post("/start", async (req, res) => {
  try {
    if (!onboardingWorkflow) {
      return res.status(501).json({
        ok: false,
        error: "onboarding_not_ready",
        message: "Onboarding workflow not available yet"
      });
    }

    const { site, ownerEmail } = req.body || {};
    if (!site) {
      return res.status(400).json({ ok: false, error: "missing_site" });
    }

    const result = await onboardingWorkflow.startOnboarding({
      site,
      ownerEmail: ownerEmail || null
    });

    return res.json({ ok: true, data: result });
  } catch (e) {
    console.error("onboarding/start error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

/**
 * POST /onboarding/message
 * Handles onboarding Q&A conversation
 */
router.post("/message", async (req, res) => {
  try {
    if (!onboardingWorkflow) {
      return res.status(501).json({
        ok: false,
        error: "onboarding_not_ready",
        message: "Onboarding workflow not available yet"
      });
    }

    const { sessionId, message } = req.body || {};
    if (!sessionId || !message) {
      return res.status(400).json({ ok: false, error: "missing_session_or_message" });
    }

    const result = await onboardingWorkflow.handleMessage({
      sessionId,
      message
    });

    return res.json({ ok: true, data: result });
  } catch (e) {
    console.error("onboarding/message error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

/**
 * POST /onboarding/complete
 * Finalize onboarding and save company profile
 */
router.post("/complete", async (req, res) => {
  try {
    if (!onboardingWorkflow) {
      return res.status(501).json({
        ok: false,
        error: "onboarding_not_ready",
        message: "Onboarding workflow not available yet"
      });
    }

    const { sessionId } = req.body || {};
    if (!sessionId) {
      return res.status(400).json({ ok: false, error: "missing_sessionId" });
    }

    const result = await onboardingWorkflow.completeOnboarding({
      sessionId
    });

    return res.json({ ok: true, data: result });
  } catch (e) {
    console.error("onboarding/complete error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

module.exports = router;
