// workflows/analytics.workflow.js
// SMB Analytics workflow (Zendesk-inspired, simplified)
//
// Purpose:
// - Aggregate meaningful business metrics
// - Power PDF reports (weekly / monthly)
// - No UI, no dashboards
//
// Depends on existing tables:
// - sites
// - conversations
// - messages
// - usage_daily
// - escalations

// -------------------------------
// Helpers
// -------------------------------
function getDateRange(period = "weekly") {
  const now = new Date();
  const end = new Date(now);
  let start;

  if (period === "monthly") {
    start = new Date(now.getFullYear(), now.getMonth(), 1);
  } else {
    // weekly (last 7 days)
    start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  }

  return {
    start: start.toISOString(),
    end: end.toISOString()
  };
}

function hourBucket(ts) {
  const d = new Date(ts);
  return d.getHours();
}

// -------------------------------
// Core aggregations
// -------------------------------
async function getConversationStats(pool, siteId, range) {
  const sql = `
    SELECT COUNT(*)::int AS total
    FROM conversations
    WHERE site_id = $1
      AND created_at BETWEEN $2 AND $3
  `;
  const r = await pool.query(sql, [siteId, range.start, range.end]);
  return { totalConversations: r.rows[0]?.total || 0 };
}

async function getChannelBreakdown(pool, siteId, range) {
  const sql = `
    SELECT
      COALESCE(m.page_url, 'unknown') AS channel,
      COUNT(*)::int AS count
    FROM messages m
    JOIN conversations c ON c.id = m.conversation_id
    WHERE c.site_id = $1
      AND m.role = 'user'
      AND m.created_at BETWEEN $2 AND $3
    GROUP BY channel
  `;
  const r = await pool.query(sql, [siteId, range.start, range.end]);

  const channels = {};
  for (const row of r.rows) {
    const key = row.channel && row.channel.includes("http") ? "web" : "unknown";
    channels[key] = (channels[key] || 0) + row.count;
  }
  return channels;
}

async function getEscalationStats(pool, siteId, range) {
  const sql = `
    SELECT COUNT(*)::int AS escalated
    FROM escalations
    WHERE site_id = $1
      AND created_at BETWEEN $2 AND $3
  `;
  const r = await pool.query(sql, [siteId, range.start, range.end]);
  return { escalated: r.rows[0]?.escalated || 0 };
}

async function getTopIntents(pool, siteId, range) {
  const sql = `
    SELECT intent, COUNT(*)::int AS count
    FROM escalations
    WHERE site_id = $1
      AND created_at BETWEEN $2 AND $3
    GROUP BY intent
    ORDER BY count DESC
    LIMIT 5
  `;
  const r = await pool.query(sql, [siteId, range.start, range.end]);
  return r.rows.map(r => ({
    intent: r.intent || "general",
    count: r.count
  }));
}

async function getPeakHours(pool, siteId, range) {
  const sql = `
    SELECT created_at
    FROM messages m
    JOIN conversations c ON c.id = m.conversation_id
    WHERE c.site_id = $1
      AND m.role = 'user'
      AND m.created_at BETWEEN $2 AND $3
  `;
  const r = await pool.query(sql, [siteId, range.start, range.end]);

  const buckets = new Array(24).fill(0);
  for (const row of r.rows) {
    buckets[hourBucket(row.created_at)]++;
  }

  return buckets.map((count, hour) => ({
    hour,
    count
  }));
}

async function getKnowledgeGaps(pool, siteId, range) {
  const sql = `
    SELECT intent, COUNT(*)::int AS count
    FROM escalations
    WHERE site_id = $1
      AND created_at BETWEEN $2 AND $3
    GROUP BY intent
    ORDER BY count DESC
  `;
  const r = await pool.query(sql, [siteId, range.start, range.end]);

  return r.rows.map(r => ({
    topic: r.intent || "unknown",
    occurrences: r.count
  }));
}

// -------------------------------
// Main public API
// -------------------------------
async function generateAnalytics({
  pool,
  site,
  period = "weekly"
}) {
  if (!pool) throw new Error("DB pool is required");
  if (!site || !site.id) throw new Error("Valid site required");

  const range = getDateRange(period);

  // Core stats
  const conversationStats = await getConversationStats(pool, site.id, range);
  const escalationStats = await getEscalationStats(pool, site.id, range);

  const aiHandled = Math.max(
    conversationStats.totalConversations - escalationStats.escalated,
    0
  );

  // Detailed breakdowns
  const channels = await getChannelBreakdown(pool, site.id, range);
  const topIntents = await getTopIntents(pool, site.id, range);
  const peakHours = await getPeakHours(pool, site.id, range);
  const knowledgeGaps = await getKnowledgeGaps(pool, site.id, range);

  // Business value estimates (SMB-friendly)
  const estimatedMinutesSaved = aiHandled * 5; // assume 5 mins per convo
  const estimatedHoursSaved = Math.round((estimatedMinutesSaved / 60) * 10) / 10;

  return {
    meta: {
      site: site.domain,
      period,
      from: range.start,
      to: range.end
    },

    summary: {
      totalConversations: conversationStats.totalConversations,
      aiHandled,
      escalated: escalationStats.escalated,
      aiResolutionRate:
        conversationStats.totalConversations > 0
          ? Math.round((aiHandled / conversationStats.totalConversations) * 100)
          : 0,
      estimatedHoursSaved
    },

    channels,
    topIntents,
    peakHours,
    knowledgeGaps
  };
}

// -------------------------------
// Export
// -------------------------------
module.exports = {
  generateAnalytics
};
