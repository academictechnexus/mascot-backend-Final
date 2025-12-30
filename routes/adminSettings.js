const express = require("express");
const router = express.Router();
const adminAuth = require("../middleware/adminAuth");

/* =========================
   GET GLOBAL SETTINGS
========================= */
router.get("/global", adminAuth, async (req, res) => {
  const { rows } = await req.db.query(
    "SELECT * FROM global_settings LIMIT 1"
  );
  res.json(rows[0]);
});

/* =========================
   UPDATE GLOBAL SETTINGS
========================= */
router.put("/global", adminAuth, async (req, res) => {
  const {
    demo_days,
    demo_daily_quota,
    ai_enabled,
    learning_enabled,
    tone,
    temperature,
    max_tokens,
    system_prompt,
    blocked_topics
  } = req.body;

  const { rows } = await req.db.query(
    `UPDATE global_settings
     SET
       demo_days = COALESCE($1, demo_days),
       demo_daily_quota = COALESCE($2, demo_daily_quota),
       ai_enabled = COALESCE($3, ai_enabled),
       learning_enabled = COALESCE($4, learning_enabled),
       tone = COALESCE($5, tone),
       temperature = COALESCE($6, temperature),
       max_tokens = COALESCE($7, max_tokens),
       system_prompt = COALESCE($8, system_prompt),
       blocked_topics = COALESCE($9, blocked_topics),
       updated_at = NOW()
     WHERE id = TRUE
     RETURNING *`,
    [
      demo_days,
      demo_daily_quota,
      ai_enabled,
      learning_enabled,
      tone,
      temperature,
      max_tokens,
      system_prompt,
      blocked_topics
    ]
  );

  res.json(rows[0]);
});

/* =========================
   SITE AI OVERRIDE
========================= */
router.get("/site/:siteId", adminAuth, async (req, res) => {
  const { siteId } = req.params;
  const { rows } = await req.db.query(
    "SELECT * FROM site_ai_settings WHERE site_id = $1",
    [siteId]
  );
  res.json(rows[0] || {});
});

router.put("/site/:siteId", adminAuth, async (req, res) => {
  const { siteId } = req.params;
  const {
    ai_enabled,
    learning_enabled,
    tone,
    temperature,
    max_tokens,
    system_prompt,
    blocked_topics
  } = req.body;

  const { rows } = await req.db.query(
    `INSERT INTO site_ai_settings (
        site_id, ai_enabled, learning_enabled,
        tone, temperature, max_tokens,
        system_prompt, blocked_topics
     )
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     ON CONFLICT (site_id) DO UPDATE SET
       ai_enabled = EXCLUDED.ai_enabled,
       learning_enabled = EXCLUDED.learning_enabled,
       tone = EXCLUDED.tone,
       temperature = EXCLUDED.temperature,
       max_tokens = EXCLUDED.max_tokens,
       system_prompt = EXCLUDED.system_prompt,
       blocked_topics = EXCLUDED.blocked_topics,
       updated_at = NOW()
     RETURNING *`,
    [
      siteId,
      ai_enabled,
      learning_enabled,
      tone,
      temperature,
      max_tokens,
      system_prompt,
      blocked_topics
    ]
  );

  res.json(rows[0]);
});

module.exports = router;
