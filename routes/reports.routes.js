// routes/reports.routes.js
// Routes to generate and send PDF business reports to owners
// Thin HTTP layer — delegates everything to workflow

const express = require("express");
const router = express.Router();

let reportWorkflow = null;
try {
  reportWorkflow = require("../workflows/report.workflow");
} catch (e) {
  // workflow not ready yet
  reportWorkflow = null;
}

/**
 * POST /reports/generate
 * Generates a PDF report for a site (no sending)
 */
router.post("/generate", async (req, res) => {
  try {
    if (!reportWorkflow) {
      return res.status(501).json({
        ok: false,
        error: "report_workflow_not_ready"
      });
    }

    const { site, period } = req.body || {};
    if (!site) {
      return res.status(400).json({ ok: false, error: "missing_site" });
    }

    const result = await reportWorkflow.generateReport({
      site,
      period: period || "weekly" // weekly | monthly
    });

    return res.json({
      ok: true,
      report: {
        reportId: result.reportId,
        filePath: result.filePath
      }
    });
  } catch (e) {
    console.error("reports/generate error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

/**
 * POST /reports/send
 * Generates and sends PDF report to business owner
 */
router.post("/send", async (req, res) => {
  try {
    if (!reportWorkflow) {
      return res.status(501).json({
        ok: false,
        error: "report_workflow_not_ready"
      });
    }

    const { site, period, sendTo } = req.body || {};
    if (!site) {
      return res.status(400).json({ ok: false, error: "missing_site" });
    }

    const result = await reportWorkflow.generateAndSend({
      site,
      period: period || "weekly",
      sendTo: sendTo || "owner" // owner | email
    });

    return res.json({
      ok: true,
      message: "Report generated and sent",
      reportId: result.reportId
    });
  } catch (e) {
    console.error("reports/send error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

module.exports = router;
