// api/index.js
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());

// ✅ CORS 설정 (프론트 도메인 허용)
app.use(
  cors({
    origin: [
      "https://jhyeein.github.io", // 깃허브 페이지
      "http://localhost:5500",     // 로컬 테스트
      "http://127.0.0.1:5500"
    ],
    methods: ["GET", "POST"]
  })
);

// ✅ Neon DB 연결
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ✅ 헬스체크 (https://도메인/api)
app.get("/", (req, res) => {
  res.json({ ok: true, message: "API is working!" });
});

// ✅ 회원가입 (POST /api/signup)
app.post("/signup", async (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) {
    return res.status(400).json({ message: "입력값 확인 필요" });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      "INSERT INTO users (user_id, password_hash) VALUES ($1,$2)",
      [userId, hash]
    );
    res.status(201).json({ message: "회원가입 성공" });
  } catch (e) {
    if (e.code === "23505") {
      return res.status(409).json({ message: "이미 존재하는 아이디입니다." });
    }
    console.error(e);
    res.status(500).json({ message: "서버 오류" });
  }
});

// ✅ 로그인 (POST /api/login)
app.post("/login", async (req, res) => {
  const { userId, password } = req.body;
  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE user_id=$1",
      [userId]
    );
    const row = result.rows[0];
    if (!row) {
      return res
        .status(401)
        .json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });
    }

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) {
      return res
        .status(401)
        .json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });
    }

    res.json({ message: "로그인 성공", user: { userId: row.user_id } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "서버 오류" });
  }
});

// ✅ Vercel 서버리스 핸들러
module.exports = (req, res) => app(req, res);
