import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export default async function handler(req, res) {
  const db = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
  });

  const { method, url } = req;

  // ================= REGISTER =================
  if (method === "POST" && url.includes("/register")) {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    const [existing] = await db.execute(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (existing.length > 0) {
      return res.status(409).json({ success: false, message: "User exists" });
    }

    const hashed = await bcrypt.hash(password, 10);

    await db.execute(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashed]
    );

    return res.json({ success: true, message: "Registered successfully" });
  }

  // ================= LOGIN =================
  if (method === "POST" && url.includes("/login")) {
    const { username, password } = req.body;

    const [result] = await db.execute(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (result.length === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const user = result[0];

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ success: false, message: "Wrong password" });
    }

    const token = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.json({ success: true, message: "Login successful", token });
  }

  return res.status(404).json({ message: "Not found" });
}