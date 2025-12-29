const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("../../db");

const router = express.Router();

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query(
    "SELECT * FROM admins WHERE username=$1",
    [username]
  );

  if (!result.rows.length) {
    return res.status(401).json({ error: "invalid_credentials" });
  }

  const admin = result.rows[0];
  const valid = await bcrypt.compare(password, admin.password_hash);

  if (!valid) {
    return res.status(401).json({ error: "invalid_credentials" });
  }

  const token = jwt.sign(
    { admin_id: admin.id, role: "admin" },
    process.env.ADMIN_JWT_SECRET,
    { expiresIn: "8h" }
  );

  res.json({ token });
});

module.exports = router;
