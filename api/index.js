const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs"); 
const cors = require("cors");

const app = express();

// middleware
app.use(cors());
app.use(express.json());

// ✅ MySQL connection pool
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// 🔐 REGISTER
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.send("❌ Please fill all fields");
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = "INSERT INTO users (username, password) VALUES (?, ?)";
    db.query(sql, [username, hashedPassword], (err) => {
      if (err) {
        console.log(err);
        return res.send("❌ Error registering user");
      }
      res.send("✅ User registered");
    });

  } catch (err) {
    console.log(err);
    res.send("❌ Error hashing password");
  }
});

// 🔑 LOGIN
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.send("❌ Please fill all fields");
  }

  const sql = "SELECT * FROM users WHERE username = ?";
  db.query(sql, [username], async (err, result) => {
    if (err) {
      console.log(err);
      return res.send("❌ DB error");
    }

    if (result.length === 0) {
      return res.send("❌ User not found");
    }

    const user = result[0];

    const match = await bcrypt.compare(password, user.password);

    if (match) {
      res.send("✅ Login successful");
    } else {
      res.send("❌ Wrong password");
    }
  });
});

module.exports = app;