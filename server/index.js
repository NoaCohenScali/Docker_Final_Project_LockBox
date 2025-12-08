require("dotenv").config();
const express = require("express");
const app = express();
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { encrypt, decrypt } = require("./EncryptionHandler");

const PORT = 3001;
const saltRounds = 10;

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

        res.json({ message: "Login ok", userId: user.id });
      });
    }
  );
});

// -------- PASSWORDS API  --------

app.post("/addpassword", (req, res) => {
  const { password, title, user_id } = req.body;
  if (!password || !title || !user_id) {
    return res
      .status(400)
      .json({ message: "Password, title, and user_id are required" });
  }
  const hashedPassword = encrypt(password);
  db.query(
    "INSERT INTO passwords (passwords, title, iv, user_id) VALUES (?,?,?,?)",
    [hashedPassword.password, title, hashedPassword.iv, user_id],
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.json({message: "Success"});
      }
    }
  );
});

app.get("/showpasswords", (req, res) => {
  const user_id = req.query.user_id;  // <-- התיקון המרכזי

  if (!user_id) {
    return res
      .status(400)
      .json({ message: "user_id is required" });
  }

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


app.delete("/deletepassword/:id", (req, res) => {
  db.query(
    "DELETE FROM passwords WHERE id = ?",
    req.params.id,
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.send(result);
      }
    }
  );
});

app.put("/updatepassword/:id", (req, res) => {
  const hashedPassword = encrypt(req.body.password);
  db.query(
    "UPDATE passwords SET passwords = ?, iv = ? WHERE id = ?",
    [hashedPassword.password, hashedPassword.iv, req.params.id],
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.send(result);
      }
    }
  );
});

app.post("/decryptpassword", (req, res) => {
  res.send(decrypt(req.body));
});

app.listen(PORT, () => {
  console.log("Server is running");
});