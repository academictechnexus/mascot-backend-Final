// middleware/adminAuth.js
// Admin JWT verification middleware (PRODUCTION SAFE)

const jwt = require("jsonwebtoken");

module.exports = function adminAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "unauthorized",
        message: "Authorization header missing or invalid"
      });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.ADMIN_JWT_SECRET);

    // attach admin info to request
    req.admin = {
      id: decoded.id,
      username: decoded.username,
      role: decoded.role
    };

    next();
  } catch (err) {
    return res.status(401).json({
      error: "unauthorized",
      message: "Invalid or expired token"
    });
  }
};
