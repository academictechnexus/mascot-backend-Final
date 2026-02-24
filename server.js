```javascript
const express = require('express');
const multer  = require('multer')
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require('crypto');
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3001;
let JWT_SECRET = "mysecret";

if (process.env.NODE_ENV === 'production') {
  JWT_SECRET = process.env.JWT_SECRET;
}

const db = require('./db');

// Middleware to authenticate admin users
const adminAuth = async (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (token == null) return res.sendStatus(401)

  jwt.verify(token, JWT_SECRET, (err, user) => {
    console.log(err)
    if (err) return res.sendStatus(403)
    req.user = user
    next()
  })
}

// Middleware to authenticate client users
const clientAuth = async (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (token == null) return res.sendStatus(401)

  jwt.verify(token, JWT_SECRET, async (err, user) => {
    console.log(err)
    if (err) return res.sendStatus(403)
    
    const clientUser = await db.query('SELECT * FROM client_users WHERE id = $1', [user.id]);
    if (!clientUser.rows[0]) {
      return res.status(404).json({ error: "Client user not found" });
    }
    
    req.user = user
    next()
  })
}

// Middleware to authenticate admin or client users
const anyAuth = async (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (token == null) return res.sendStatus(401)

  jwt.verify(token, JWT_SECRET, async (err, user) => {
    console.log(err)
    if (err) return res.sendStatus(403)
    
    const clientUser = await db.query('SELECT * FROM client_users WHERE id = $1', [user.id]);
    if (!clientUser.rows[0]) {
      // check for admin user
      const adminUser = await db.query('SELECT * FROM users WHERE id = $1', [user.id]);
      if (!adminUser.rows[0]) {
        return res.status(404).json({ error: "Admin or Client user not found" });
      }
    }
    
    req.user = user
    next()
  })
}

// Routes
app.get('/', (req, res) => {
  res.send('Mascot backend is running');
});

app.post("/auth/admin", async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const userResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = userResult.rows[0];
  
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const passwordValid = await bcrypt.compare(password, user.password_hash);

  if (!passwordValid) {
    return res.status(401).json({ error: "Invalid password" });
  }
  
  const token = jwt.sign({ id: user.id }, JWT_SECRET);

  res.json({ token, user });
});

app.post("/auth/client", async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const userResult = await db.query('SELECT * FROM client_users WHERE email = $1', [email]);
  const user = userResult.rows[0];
  
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const passwordValid = await bcrypt.compare(password, user.password_hash);

  if (!passwordValid) {<｜begin▁of▁sentence｜>
