const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());

// DB 연결
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// 헬스체크(브라우저로 확인 용)
app.get("/", (req, res) => res.json({ ok: true }));

// 회원가입 (⚠️ /api 붙이지 말기)
app.post("/signup", async (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) return res.status(400).json({ message: "입력값 확인 필요" });

  try {
    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      "INSERT INTO users (user_id, password_hash) VALUES ($1,$2)",
      [userId, hash]
    );
    res.status(201).json({ message: "회원가입 성공" });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ message: "이미 존재하는 아이디입니다." });
    console.error(e);
    res.status(500).json({ message: "서버 오류" });
  }
});

// 로그인 (⚠️ /api 붙이지 말기, 앞에 슬래시 추가)
app.post("/login", async (req, res) => {
  const { userId, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE user_id=$1", [userId]);
  const row = result.rows[0];
  if (!row) return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });

  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });

  res.json({ message: "로그인 성공", user: { userId: row.user_id } });
});

// Vercel 서버리스
module.exports = app;
