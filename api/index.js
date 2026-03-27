import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";

// ================= INIT =================
const app = express();
app.use(express.json());

// ================= RATE LIMITERS =================
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, message: "Too many requests" }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { success: false, message: "Too many login attempts" }
});

app.use(globalLimiter);

// ================= DATABASE =================
let connection;
async function getDB() {
  if (connection) return connection;
  connection = await mysql.createConnection(process.env.DATABASE_URL);
  return connection;
}

// ================= HELPERS =================
function validateInput(username, password) {
  if (!username || !password) return "Missing username or password";
  if (username.length < 3) return "Username too short";
  if (password.length < 6) return "Password must be at least 6 chars";
  return null;
}

function getToken(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return null;
  return auth.split(" ")[1];
}

function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

// ================= ROUTES =================

// REGISTER
app.post("/register", async (req, res) => {
  try {
    const db = await getDB();
    const { username, password } = req.body;

    const error = validateInput(username, password);
    if (error) return res.status(400).json({ success: false, message: error });

    const [existing] = await db.execute(
      "SELECT id FROM users WHERE username = ?",
      [username]
    );

    if (existing.length > 0) {
      return res.status(409).json({ success: false, message: "User already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);

    await db.execute(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashed]
    );

    return res.status(201).json({ success: true, message: "Registered" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// LOGIN
app.post("/login", loginLimiter, async (req, res) => {
  try {
    const db = await getDB();
    const { username, password } = req.body;

    const error = validateInput(username, password);
    if (error) return res.status(400).json({ success: false, message: error });

    const [rows] = await db.execute(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.status(200).json({ success: true, token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// ME
app.get("/me", async (req, res) => {
  const token = getToken(req);

  if (!token) {
    return res.status(401).json({ success: false, message: "No token" });
  }

  const decoded = verifyToken(token);

  if (!decoded) {
    return res.status(401).json({ success: false, message: "Invalid token" });
  }

  return res.status(200).json({ success: true, user: decoded });
});

// CHANGE PASSWORD
app.post("/change-password", async (req, res) => {
  try {
    const db = await getDB();
    const token = getToken(req);

    if (!token) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ success: false, message: "Invalid token" });
    }

    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    const [rows] = await db.execute(
      "SELECT password FROM users WHERE id = ?",
      [decoded.id]
    );

    const user = rows[0];

    const match = await bcrypt.compare(oldPassword, user.password);
    if (!match) {
      return res.status(401).json({ success: false, message: "Old password incorrect" });
    }

    const hashed = await bcrypt.hash(newPassword, 10);

    await db.execute(
      "UPDATE users SET password = ? WHERE id = ?",
      [hashed, decoded.id]
    );

    return res.status(200).json({ success: true, message: "Password updated" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================= START SERVER =================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
