require("dotenv").config();
const express = require("express");
const app = express();
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { encrypt, decrypt } = require("./EncryptionHandler");

const PORT = 3001;
const saltRounds = 10;
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
      console.log(err);
      return res.status(401).json({ message: "Invalid or expired token" });
    }

    req.user = {
      id: decoded.userId,
      email: decoded.email,
    };

    next();
  });
}


app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});


// -------- USERS: REGISTER + LOGIN --------

app.post("/register", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ message: "Error hashing password" });
    }

    db.query(
      "INSERT INTO users (email, password_hash) VALUES (?, ?)",
      [email, hash],
      (err, result) => {
        if (err) {
          console.log(err);
          return res.status(500).json({ message: "Error saving user" });
        }
        res.status(201).json({ message: "User created" });
      }
    );
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    (err, results) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ message: "DB error" });
      }

      if (results.length === 0) {
        return res.status(401).json({ message: "User not found" });
      }

      const user = results[0];

      bcrypt.compare(password, user.password_hash, (err, same) => {
        if (err) {
          console.log(err);
          return res.status(500).json({ message: "Error checking password" });
        }

        if (!same) {
          return res.status(401).json({ message: "Wrong password" });
        }
        const token = jwt.sign(
          { userId: user.id, email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: "2h" }
        );

        res.json({ message: "Login ok", userId: user.id, token });
      });
    }
  );
});

// -------- PASSWORDS API  --------

app.post("/addpassword", authMiddleware, (req, res) => {
  const { password, title } = req.body;
  const user_id = req.user.id;  // מגיע מה־token

  if (!password || !title) {
    return res
      .status(400)
      .json({ message: "Password and title are required" });
  }

  const hashedPassword = encrypt(password);
  db.query(
    "INSERT INTO passwords (passwords, title, iv, user_id) VALUES (?,?,?,?)",
    [hashedPassword.password, title, hashedPassword.iv, user_id],
    (err, result) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ message: "DB error" });
      } else {
        res.json({ message: "Success" });
      }
    }
  );
});

app.get("/showpasswords", authMiddleware, (req, res) => {
  const user_id = req.user.id;

  db.query(
    "SELECT * FROM passwords WHERE user_id = ?;",
    [user_id],
    (err, result) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ message: "DB error" });
      } else {
        res.json(result);
      }
    }
  );
});


app.delete("/deletepassword/:id", authMiddleware, (req, res) => {
  const user_id = req.user.id;

  db.query(
    "DELETE FROM passwords WHERE id = ? AND user_id = ?",
    [req.params.id, user_id],
    (err, result) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ message: "DB error" });
      } else {
        res.send(result);
      }
    }
  );
});


app.put("/updatepassword/:id", authMiddleware, (req, res) => {
  const hashedPassword = encrypt(req.body.password);
  const user_id = req.user.id;

  db.query(
    "UPDATE passwords SET passwords = ?, iv = ? WHERE id = ? AND user_id = ?",
    [hashedPassword.password, hashedPassword.iv, req.params.id, user_id],
    (err, result) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ message: "DB error" });
      } else {
        res.send(result);
      }
    }
  );
});

app.post("/decryptpassword", authMiddleware, (req, res) => {
  try {
    const plain = decrypt(req.body);
    res.send(plain);
  } catch (err) {
    console.log(err);
    res.status(400).json({ message: "Decrypt failed" });
  }
});

app.listen(PORT, () => {
  console.log("Server is running");
});