const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const { ethers } = require("ethers"); // 기존 그대로

const app = express();
app.use(express.json());

// CORS: 프론트 도메인 허용 (기존 그대로)
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

// 회원가입: POST /api/signup (기존 그대로)
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

// 로그인: POST /api/login (기존 그대로)
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

// (참고) 예전 서버 생성 API는 그대로 두지만, 이제 프론트에서 호출하지 않게 바꿈.
// 지갑 생성(서버 생성; private_key 사용) - 더 이상 사용하지 않지만 레거시 호환용
app.post("/api/wallet/create", async (req, res) => {
  const { userId } = req.body;
  if (!userId) {
    return res.status(400).json({ message: "userId 필요" });
  }

  try {
    const wallet = ethers.Wallet.createRandom();
    // ❗ private_key 컬럼을 삭제했다면 이 API는 실패합니다. (프론트가 호출하지 않으니 무시)
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

/* ===================== ✅ 추가: 클라이언트 생성 지갑 저장 ===================== */
/**
 * POST /api/wallet/save
 * body: { userId, address, keystore }
 * - 서버는 private_key를 받지 않음/보관하지 않음
 * - DB에는 address + keystore_json만 저장
 */
app.post("/api/wallet/save", async (req, res) => {
  const { userId, address, keystore } = req.body;
  if (!userId || !address || !keystore) {
    return res.status(400).json({ message: "userId, address, keystore 필요" });
  }
  try {
    await pool.query(
      "INSERT INTO wallets (user_id, address, keystore_json) VALUES ($1,$2,$3)",
      [userId, address, keystore]
    );
    res.json({ message: "지갑 저장 성공", address });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "지갑 저장 실패" });
  }
});
/* ============================================================================ */

// Vercel 서버리스 함수 핸들러
module.exports = (req, res) => app(req, res);
