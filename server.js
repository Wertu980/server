import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pkg from "pg";
import dotenv from "dotenv";

dotenv.config();
const { Pool } = pkg;

// --- NeonDB connection ---
const pool = new Pool({
  connectionString: process.env.NEON_DATABASE_URL
});

const app = express();
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRE_DAYS = parseInt(process.env.JWT_EXPIRE_DAYS || 30);

// --- Signup ---
app.post("/signup", async (req, res) => {
  const { name, mobile, gender, age, password, confirmPassword } = req.body;

  if (!name || !mobile || !gender || !age || !password || !confirmPassword)
    return res.status(400).json({ error: "All fields required" });

  if (password !== confirmPassword)
    return res.status(400).json({ error: "Passwords do not match" });

  if (age < 18)
    return res.status(400).json({ error: "Minimum age is 18" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const userExists = await pool.query("SELECT * FROM users WHERE mobile=$1", [mobile]);
    if (userExists.rows.length)
      return res.status(400).json({ error: "User already exists" });

    const result = await pool.query(
      `INSERT INTO users (name, mobile, gender, age, password, created_at)
       VALUES ($1,$2,$3,$4,$5,NOW()) RETURNING id,name,mobile,gender,age`,
      [name, mobile, gender, age, hashedPassword]
    );

    res.json({ message: "Signup successful", user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// --- Login ---
app.post("/login", async (req, res) => {
  const { mobile, password } = req.body;

  if (!mobile || !password)
    return res.status(400).json({ error: "Mobile & password required" });

  try {
    const result = await pool.query("SELECT * FROM users WHERE mobile=$1", [mobile]);
    if (!result.rows.length)
      return res.status(400).json({ error: "User not found" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ error: "Incorrect password" });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: `${JWT_EXPIRE_DAYS}d` });

    res.json({ message: "Login successful", token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// --- Refresh Token ---
app.post("/refresh", (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: "Token required" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const newToken = jwt.sign({ id: decoded.id }, JWT_SECRET, { expiresIn: `${JWT_EXPIRE_DAYS}d` });
    res.json({ token: newToken });
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
});

// --- Me (get current user) ---
app.get("/me", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query("SELECT id,name,mobile,gender,age FROM users WHERE id=$1", [decoded.id]);
    res.json({ user: result.rows[0] });
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
});

// --- Server Listen ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Auth server running on port ${PORT}`));