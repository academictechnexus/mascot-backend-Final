// workflows/report.workflow.js
// Orchestrates analytics → charts → PDF → notification
//
// This is the single entry point for business reports.
// Used by routes/reports.routes.js

const path = require("path");
const fs = require("fs");

// Workflows & services
const analyticsWorkflow = require("./analytics.workflow");
const chartService = require("../services/chart.service");
const pdfService = require("../services/pdf.service");
const notificationService = require("../services/notification.service");

// -------------------------------
// Helpers
// -------------------------------
function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function getOutputBaseDir() {
  return path.join(__dirname, "..", "generated-reports");
}

// -------------------------------
// Core functions
// -------------------------------

/**
 * Generate report only (no send)
 */
async function generateReport({
  pool,
  site,
  period = "weekly"
}) {
  if (!pool) throw new Error("DB pool is required");
  if (!site || !site.id) throw new Error("Valid site is required");

  const baseDir = getOutputBaseDir();
  const siteDir = path.join(baseDir, site.domain);
  const chartsDir = path.join(siteDir, "charts");

  ensureDir(chartsDir);

  // 1️⃣ Analytics
  const analytics = await analyticsWorkflow.generateAnalytics({
    pool,
    site,
    period
  });

  // 2️⃣ Charts
  const charts = await chartService.buildReportCharts({
    analytics,
    outputDir: chartsDir
  });

  // 3️⃣ PDF
  const pdfPath = await pdfService.generatePdfReport({
    site,
    analytics,
    charts,
    outputDir: siteDir
  });

  return {
    reportId: path.basename(pdfPath),
    filePath: pdfPath,
    period,
    generatedAt: new Date().toISOString()
  };
}

/**
 * Generate report AND send to owner
 */
async function generateAndSend({
  pool,
  site,
  period = "weekly",
  sendTo = "owner"
}) {
  const result = await generateReport({
    pool,
    site,
    period
  });

  // 4️⃣ Notify owner (attach PDF)
  try {
    if (sendTo === "owner") {
      await notificationService.notifyOwner({
        site,
        ticketId: result.reportId,
        channel: "report",
        summary: `Your ${period} AI Support Performance Report is ready.`,
        customerContact: null,
        attachmentPath: result.filePath
      });
    }
  } catch (e) {
    console.warn("Report notification failed:", e.message || e);
  }

  return result;
}

// -------------------------------
// Export
// -------------------------------
module.exports = {
  generateReport,
  generateAndSend
};
