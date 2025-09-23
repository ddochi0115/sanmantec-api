// api/index.js
const express = require("express");
const serverless = require("serverless-http"); // ★ 추가
const cors = require("cors");                  // ★ CORS 추가
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

// 풀은 콜드스타트마다 재생성되지 않게 전역에 보관
let _pool;
function getPool() {
  if (!_pool) {
    _pool = new Pool({
      connectionString: process.env.DATABASE_URL, // Neon의 DATABASE_URL 그대로
      ssl: { rejectUnauthorized: false },         // Neon은 SSL 필요
    });
  }
  return _pool;
}

const app = express();
app.use(express.json());

// ★ CORS: 프론트 도메인 허용 (필요한 도메인만 넣자)
app.use(
  cors({
    origin: [
      "https://jhyeein.github.io",        // 깃허브 페이지
      "http://localhost:5500",            // 로컬 미리보기 쓰면 추가
      "http://127.0.0.1:5500",
    ],
    methods: ["GET", "POST"],
  })
);

// Health check → https://<프로젝트>.vercel.app/api
app.get("/", (req, res) => res.json({ ok: true, message: "API is working!" }));

// 회원가입
app.post("/signup", async (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) {
    return res.status(400).json({ message: "입력값 확인 필요" });
  }
  try {
    const pool = getPool();
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

// 로그인
app.post("/login", async (req, res) => {
  const { userId, password } = req.body;
  try {
    const pool = getPool();
    const result = await pool.query(
      "SELECT * FROM users WHERE user_id=$1",
      [userId]
    );
    const row = result.rows[0];
    if (!row) return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });
    res.json({ message: "로그인 성공", user: { userId: row.user_id } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "서버 오류" });
  }
});

// ★ 여기! Express 앱을 서버리스 핸들러로 래핑해 export
module.exports = serverless(app);
