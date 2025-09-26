const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
// const { ethers } = require("ethers"); // 기존 그대로 두되, 서버에선 지갑 생성 안 씀

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

/**
 * 지갑 생성(저장): 클라이언트에서 생성/암호화 → 서버는 저장만
 * ✅ 변경점:
 *  - 요청 바디: { userId, address, keystore }
 *  - DB 저장: wallets(user_id, address, keystore_json)
 *  - private_key는 더 이상 받지도/저장하지도 않음
 */
app.post("/api/wallet/create", async (req, res) => {
  const { userId, address, keystore } = req.body; // ✅ CHANGED
  if (!userId || !address || !keystore) {
    return res.status(400).json({ message: "userId, address, keystore 필요" });
  }

  try {
    await pool.query(
      "INSERT INTO wallets (user_id, address, keystore_json) VALUES ($1,$2,$3)", // ✅ CHANGED
      [userId, address, keystore]
    );
    res.json({ message: "지갑 저장 성공", address });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "지갑 생성 실패" });
  }
});

// Vercel 서버리스 함수 핸들러
module.exports = (req, res) => app(req, res);
