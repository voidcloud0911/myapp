import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

let connection;

async function getDB() {
  if (connection) return connection;
  connection = await mysql.createConnection(process.env.DATABASE_URL);
  return connection;
}

function verifyToken(req) {
  const auth = req.headers.authorization;
  if (!auth) return null;

  try {
    const token = auth.split(" ")[1];
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

export default async function handler(req, res) {
  try {
    const db = await getDB();
    const path = req.url;

    // ================= REGISTER =================
    if (req.method === "POST" && path.includes("/register")) {
      const { username, password } = req.body;

      if (!username || !password) {
        return res.json({ success: false, message: "Fill all fields" });
      }

      const [existing] = await db.execute(
        "SELECT id FROM users WHERE username = ?",
        [username]
      );

      if (existing.length > 0) {
        return res.json({ success: false, message: "User exists" });
      }

      const hashed = await bcrypt.hash(password, 10);

      await db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hashed]
      );

      return res.json({ success: true, message: "Registered" });
    }

    // ================= LOGIN =================
    if (req.method === "POST" && path.includes("/login")) {
      const { username, password } = req.body;

      const [rows] = await db.execute(
        "SELECT * FROM users WHERE username = ?",
        [username]
      );

      if (rows.length === 0) {
        return res.json({ success: false, message: "User not found" });
      }

      const user = rows[0];
      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        return res.json({ success: false, message: "Wrong password" });
      }

      const token = jwt.sign(
        { id: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );

      return res.json({
        success: true,
        message: "Login success",
        token
      });
    }

    // ================= GET USER =================
    if (req.method === "GET" && path.includes("/me")) {
      const user = verifyToken(req);

      if (!user) {
        return res.json({ success: false });
      }

      return res.json({ success: true, user });
    }

    // ================= CHANGE PASSWORD =================
    if (req.method === "POST" && path.includes("/change-password")) {
      const user = verifyToken(req);

      if (!user) {
        return res.json({ success: false, message: "Unauthorized" });
      }

      const { newPassword } = req.body;
      const hashed = await bcrypt.hash(newPassword, 10);

      await db.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        [hashed, user.id]
      );

      return res.json({ success: true, message: "Password updated" });
    }

    return res.json({ success: false, message: "Not found" });

  } catch (err) {
    console.error(err);
    return res.json({ success: false, message: err.message });
  }
}