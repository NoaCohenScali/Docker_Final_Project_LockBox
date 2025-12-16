require("dotenv").config();
const express = require("express");
const cors = require("cors");

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { encrypt, decrypt } = require("./EncryptionHandler");
const db = require("./config/db");

const app = express();
const saltRounds = 10;

app.use(cors());
app.use(express.json());

/* -------- HEALTH CHECK -------- */
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});

/* -------- AUTH MIDDLEWARE -------- */
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  const [scheme, token] = authHeader.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ message: "Invalid auth header" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }

    req.user = {
      id: decoded.userId,
      email: decoded.email,
    };

    next();
  });
}

/* -------- ROUTES -------- */

// register
app.post("/register", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) return res.status(500).json({ message: "Error hashing password" });

    db.query(
      "INSERT INTO users (email, password_hash) VALUES (?, ?)",
      [email, hash],
      (err) => {
        if (err) return res.status(500).json({ message: "Error saving user" });
        res.status(201).json({ message: "User created" });
      }
    );
  });
});

// login
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) return res.status(500).json({ message: "DB error" });
    if (results.length === 0)
      return res.status(401).json({ message: "User not found" });

    const user = results[0];

    bcrypt.compare(password, user.password_hash, (err, same) => {
      if (!same)
        return res.status(401).json({ message: "Wrong password" });

      const token = jwt.sign(
        { userId: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "2h" }
      );

      res.json({ message: "Login ok", userId: user.id, token });
    });
  });
});

/* passwords */
app.post("/addpassword", authMiddleware, (req, res) => {
  const { password, title } = req.body;
  const user_id = req.user.id;

  if (!password || !title) {
    return res.status(400).json({ message: "Password and title are required" });
  }

  const hashedPassword = encrypt(password);

  db.query(
    "INSERT INTO passwords (passwords, title, iv, user_id) VALUES (?,?,?,?)",
    [hashedPassword.password, title, hashedPassword.iv, user_id],
    (err) => {
      if (err) return res.status(500).json({ message: "DB error" });
      res.json({ message: "Success" });
    }
  );
});

module.exports = app;
