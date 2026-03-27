import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// ✅ Reuse connection across requests (important for Vercel)
let connection;

async function getDB() {
  if (connection) return connection;

  if (process.env.DATABASE_URL) {
    connection = await mysql.createConnection(process.env.DATABASE_URL);
  } else {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      port: process.env.DB_PORT,
      ssl: { rejectUnauthorized: false },
    });
  }

  return connection;
}

export default async function handler(req, res) {
  try {
    const db = await getDB();
    const { method, url } = req;

    // ============================
    // 🔐 REGISTER
    // ============================
    if (method === "POST" && url.includes("/register")) {
      const { username, password } = req.body;

      if (!username || !password) {
        return res.status(400).json({
          success: false,
          message: "Please fill all fields",
        });
      }

      const [existing] = await db.execute(
        "SELECT id FROM users WHERE username = ?",
        [username]
      );

      if (existing.length > 0) {
        return res.status(409).json({
          success: false,
          message: "Username already exists",
        });
      }

      const hashed = await bcrypt.hash(password, 10);

      await db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hashed]
      );

      return res.status(201).json({
        success: true,
        message: "User registered successfully",
      });
    }

    // ============================
    // 🔑 LOGIN
    // ============================
    if (method === "POST" && url.includes("/login")) {
      const { username, password } = req.body;

      if (!username || !password) {
        return res.status(400).json({
          success: false,
          message: "Please fill all fields",
        });
      }

      const [rows] = await db.execute(
        "SELECT * FROM users WHERE username = ?",
        [username]
      );

      if (rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      const user = rows[0];

      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        return res.status(401).json({
          success: false,
          message: "Wrong password",
        });
      }

      const token = jwt.sign(
        { id: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );

      return res.json({
        success: true,
        message: "Login successful",
        token,
      });
    }

    // ============================
    // ❌ NOT FOUND
    // ============================
    return res.status(404).json({
      success: false,
      message: "Route not found",
    });

  } catch (err) {
    console.error("SERVER ERROR:", err);

    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
}