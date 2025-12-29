const jwt = require("jsonwebtoken");

module.exports = function adminAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "unauthorized" });

  const token = header.split(" ")[1];

  try {
    req.admin = jwt.verify(token, process.env.ADMIN_JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "invalid_token" });
  }
};
