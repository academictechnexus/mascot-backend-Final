const express = require("express");
const pool = require("../../db");
const adminAuth = require("../middleware/adminAuth");

const router = express.Router();

/* Add site */
router.post("/", adminAuth, async (req, res) => {
  const { domain, plan } = req.body;

  const result = await pool.query(
    `INSERT INTO sites (domain, plan)
     VALUES ($1, $2)
     RETURNING *`,
    [domain, plan]
  );

  res.json(result.rows[0]);
});

/* List sites */
router.get("/", adminAuth, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM sites ORDER BY created_at DESC"
  );
  res.json(result.rows);
});

/* Update site */
router.put("/:id", adminAuth, async (req, res) => {
  const { plan, is_active } = req.body;

  const result = await pool.query(
    `UPDATE sites
     SET plan=$1, is_active=$2
     WHERE id=$3
     RETURNING *`,
    [plan, is_active, req.params.id]
  );

  res.json(result.rows[0]);
});

/* Delete site */
router.delete("/:id", adminAuth, async (req, res) => {
  await pool.query("DELETE FROM sites WHERE id=$1", [req.params.id]);
  res.json({ success: true });
});

module.exports = router;
