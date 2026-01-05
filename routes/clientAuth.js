const express = require("express");
const bcrypt = require("bcrypt");
const router = express.Router();
const { Pool } = require("pg");

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

router.post("/register", async (req, res) => {
  const { token, email, password } = req.body;

  if (!token || !email || !password) {
    return res.status(400).json({ error: "missing_fields" });
  }

  try {
    // 1. Validate setup token
    const tokenRes = await pool.query(
      `SELECT site_id FROM client_setup_tokens
       WHERE token = $1 AND used = true`,
      [token]
    );

    if (tokenRes.rowCount === 0) {
      return res.status(400).json({ error: "invalid_token" });
    }

    const site_id = tokenRes.rows[0].site_id;

    // 2. Hash password
    const hash = await bcrypt.hash(password, 10);

    // 3. Create client user
    await pool.query(
      `INSERT INTO client_users (site_id, email, password_hash)
       VALUES ($1, $2, $3)`,
      [site_id, email.toLowerCase(), hash]
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "server_error" });
  }
});

module.exports = router;
