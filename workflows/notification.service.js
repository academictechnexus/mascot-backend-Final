// services/notification.service.js
// Unified notification service for SMBs
//
// Currently supports:
// - Email notifications (primary)
// Future-ready for:
// - WhatsApp
// - SMS
//
// This service is intentionally decoupled from server.js
// to avoid breaking existing logic.

const nodemailer = require("nodemailer");

// -------------------------------
// Config & initialization
// -------------------------------
const SMTP_ENABLED = !!(
  process.env.SMTP_HOST &&
  process.env.SMTP_PORT &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS &&
  process.env.EMAIL_FROM
);

const EMAIL_FROM = process.env.EMAIL_FROM || "no-reply@example.com";

let transporter = null;

if (SMTP_ENABLED) {
  try {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || "587", 10),
      secure: parseInt(process.env.SMTP_PORT || "587", 10) === 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
    console.log("📧 Notification service: SMTP enabled");
  } catch (e) {
    console.warn("⚠️ Notification service: Failed to init SMTP:", e.message);
    transporter = null;
  }
} else {
  console.log("ℹ️ Notification service: SMTP not configured (email disabled)");
}

// -------------------------------
// Helpers
// -------------------------------
function formatOwnerEmail({ site, ticketId, channel, summary, customerContact }) {
  const subject = `New customer request – ${ticketId}`;

  const html = `
    <div style="font-family: Arial, sans-serif; line-height: 1.6">
      <h2>📩 New Customer Request</h2>

      <p><strong>Business:</strong> ${site?.name || site?.domain || "Unknown"}</p>
      <p><strong>Channel:</strong> ${channel}</p>
      <p><strong>Reference ID:</strong> <b>${ticketId}</b></p>

      <hr />

      <p><strong>Customer message summary:</strong></p>
      <p style="background:#f6f6f6;padding:10px;border-radius:4px;">
        ${summary}
      </p>

      ${
        customerContact
          ? `<p><strong>Customer contact:</strong> ${customerContact}</p>`
          : ""
      }

      <hr />

      <p style="color:#555;">
        This request was escalated by your AI assistant.
        Please follow up with the customer directly.
      </p>
    </div>
  `;

  return { subject, html };
}

// -------------------------------
// Public API
// -------------------------------

/**
 * Notify business owner of escalation
 */
async function notifyOwner({
  site,
  ticketId,
  channel,
  summary,
  customerContact
}) {
  if (!SMTP_ENABLED || !transporter) {
    console.warn(
      "⚠️ notifyOwner skipped: SMTP not enabled",
      ticketId
    );
    return false;
  }

  const ownerEmail =
    site?.owner_email ||
    site?.email ||
    site?.webhook_url || // fallback (if misused as email)
    null;

  if (!ownerEmail) {
    console.warn(
      "⚠️ notifyOwner skipped: No owner email found for site",
      site?.domain
    );
    return false;
  }

  const { subject, html } = formatOwnerEmail({
    site,
    ticketId,
    channel,
    summary,
    customerContact
  });

  try {
    await transporter.sendMail({
      from: EMAIL_FROM,
      to: ownerEmail,
      subject,
      html
    });

    console.log("✅ Owner notified:", ticketId, ownerEmail);
    return true;
  } catch (e) {
    console.error(
      "❌ Failed to send owner notification:",
      e.message || e
    );
    return false;
  }
}

/**
 * (Future) WhatsApp / SMS notification hook
 * Stub intentionally left for extension without refactor
 */
async function notifyOwnerViaWhatsApp(_payload) {
  // To be implemented:
  // - Twilio
  // - Meta WhatsApp Cloud API
  return false;
}

// -------------------------------
// Exports
// -------------------------------
module.exports = {
  notifyOwner,
  notifyOwnerViaWhatsApp
};
