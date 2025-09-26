const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const { ethers } = require("ethers"); 

const app = express();
app.use(express.json());

// CORS: 프론트 도메인 허용
app.use(
  cors({
    origin: [
      "https://jhyeein.github.io", // GitHub Pages
      "http://localhost:5500",     // 로컬 테스트
      "http://127.0.0.1:5500"
    ],
    methods: ["GET", "POST"]
  })
);

// DB 풀 (Neon)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// 헬스체크: GET /api
app.get("/api", (req, res) => {
  res.json({ ok: true, message: "API is working!" });
});

// 회원가입: POST /api/signup
app.post("/api/signup", async (req, res) => {
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

// 로그인: POST /api/login
app.post("/api/login", async (req, res) => {
  const { userId, password } = req.body;
  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE user_id=$1",
      [userId]
    );
    const row = result.rows[0];
    if (!row)
      return res
        .status(401)
        .json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok)
      return res
        .status(401)
        .json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });

    res.json({ message: "로그인 성공", user: { userId: row.user_id } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "서버 오류" });
  }
});

// 지갑 생성
app.post("/api/wallet/create", async (req, res) => {
  const { userId } = req.body;
  if (!userId) {
    return res.status(400).json({ message: "userId 필요" });
  }

  try {
    const wallet = ethers.Wallet.createRandom();
    await pool.query(
      "INSERT INTO wallets (user_id, address, private_key) VALUES ($1,$2,$3)",
      [userId, wallet.address, wallet.privateKey]
    );
    res.json({ message: "지갑 생성 성공", address: wallet.address });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "지갑 생성 실패" });
  }
});

/* ===================== ✅ 추가: 개인키 내보내기 API ===================== */
/**
 * POST /api/wallet/export
 * body: { userId, password, address }
 * 1) 사용자 비밀번호 검증
 * 2) 해당 주소가 그 사용자의 지갑인지 확인
 * 3) DB에 저장된 private_key를 반환
 */
app.post("/api/wallet/export", async (req, res) => {
  const { userId, password, address } = req.body;
  if (!userId || !password || !address) {
    return res.status(400).json({ message: "userId, password, address 필요" });
  }
  try {
    // 사용자 비번 검증
    const u = await pool.query(
      "SELECT password_hash FROM users WHERE user_id=$1",
      [userId]
    );
    const user = u.rows[0];
    if (!user) return res.status(401).json({ message: "인증 실패" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: "인증 실패" });

    // 내 지갑인지 + 개인키 존재 확인
    const w = await pool.query(
      "SELECT private_key FROM wallets WHERE user_id=$1 AND address=$2",
      [userId, address]
    );
    const row = w.rows[0];
    if (!row || !row.private_key) {
      return res.status(404).json({ message: "해당 지갑이 없거나 내보낼 키가 없습니다." });
    }

    // 최소한으로 반환
    res.json({ privateKey: row.private_key });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "개인키 내보내기 실패" });
  }
});
/* ===================================================================== */

// Vercel 서버리스 함수 핸들러
module.exports = (req, res) => app(req, res);
