const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();

// ✅ MIDDLEWARE
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname)); // serve HTML + CSS

// 🔗 DATABASE CONNECTION (uses env for deployment)
const db = mysql.createConnection({
  host: process.env.DB_HOST || "shinkansen.proxy.rlwy.net",
  port: process.env.DB_PORT || 36307,
  user: process.env.DB_USER || "appuser",
  password: process.env.DB_PASSWORD || "mypassword",
  database: process.env.DB_NAME || "railway"
});

db.connect(err => {
  if (err) {
    console.log("❌ DB connection failed:", err);
  } else {
    console.log("✅ Connected to MySQL");
  }
});

// 🏠 HOME ROUTE
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
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
    db.query(sql, [username, hashedPassword], (err, result) => {
      if (err) {
        console.log(err);
        return res.send("❌ Error registering user");
      }
      res.send("✅ User registered");
    });

  } catch (err) {
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
    if (err) return res.send("❌ DB error");

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

// 🚀 SERVER (dynamic port for deployment)
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});