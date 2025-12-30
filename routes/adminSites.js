// routes/adminSites.js
// Admin-only Site Management APIs

const express = require("express");
const router = express.Router();
const adminAuth = require("../middleware/adminAuth");

/* =========================
   GET ALL SITES
========================= */
router.get("/", adminAuth, async (req, res) => {
  try {
    const { rows } = await req.db.query(
      `SELECT
         id,
         name,
         domain,
         plan,
         daily_quota,
         status,
         created_at
       FROM sites
       ORDER BY created_at DESC`
    );

    res.json(rows);
  } catch (err) {
    console.error("GET sites error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

/* =========================
   CREATE SITE
========================= */
router.post("/", adminAuth, async (req, res) => {
  try {
    const {
      name,
      domain,
      plan = "basic",
      daily_quota = 50,
      status = "active"
    } = req.body;

    if (!name || !domain) {
      return res.status(400).json({
        error: "missing_fields",
        message: "Name and domain are required"
      });
    }

    const { rows } = await req.db.query(
      `INSERT INTO sites
        (name, domain, plan, daily_quota, status)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [name, domain, plan, daily_quota, status]
    );

    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "duplicate_domain",
        message: "Domain already exists"
      });
    }

    console.error("CREATE site error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

/* =========================
   UPDATE SITE (PLAN / QUOTA / NAME)
========================= */
router.put("/:id", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, plan, daily_quota } = req.body;

    const { rows } = await req.db.query(
      `UPDATE sites
       SET
         name = COALESCE($1, name),
         plan = COALESCE($2, plan),
         daily_quota = COALESCE($3, daily_quota)
       WHERE id = $4
       RETURNING *`,
      [name, plan, daily_quota, id]
    );

    if (!rows[0]) {
      return res.status(404).json({ error: "site_not_found" });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error("UPDATE site error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

/* =========================
   ENABLE / DISABLE SITE
========================= */
router.patch("/:id/status", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!["active", "demo", "disabled"].includes(status)) {
      return res.status(400).json({
        error: "invalid_status"
      });
    }

    const { rows } = await req.db.query(
      `UPDATE sites
       SET status = $1
       WHERE id = $2
       RETURNING *`,
      [status, id]
    );

    if (!rows[0]) {
      return res.status(404).json({ error: "site_not_found" });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error("UPDATE status error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

module.exports = router;
