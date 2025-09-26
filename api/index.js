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

// 헬스체크
app.get("/api", (req, res) => {
  res.json({ ok: true, message: "API is working!" });
});

// 회원가입
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

// 로그인
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

// (레거시) 서버에서 키 생성 API — 비권장 (프론트 생성 권장)
app.post("/api/wallet/create", async (req, res) => {
  const { userId } = req.body;
  if (!userId) {
    return res.status(400).json({ message: "userId 필요" });
  }
  try {
    const wallet = ethers.Wallet.createRandom();
    // ⚠️ 보안상 private_key 저장은 지양. (레거시 예시 유지)
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

/* ✅ 클라이언트 생성 지갑 저장: address + keystore_json 만 저장 */
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

/* ✅ 지갑 목록 (재로그인/새로고침 시 복원) */
app.get("/api/wallets/:userId", async (req, res) => {
  const { userId } = req.params;
  if (!userId) return res.status(400).json({ message: "userId 필요" });
  try {
    const result = await pool.query(
      `SELECT address, keystore_json
         FROM wallets
        WHERE user_id = $1
        ORDER BY id DESC`,
      [userId]
    );
    res.json({ wallets: result.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "지갑 목록 조회 실패" });
  }
});

/* ✅ 지갑 삭제 (비밀번호 재확인) */
app.post("/api/wallet/delete", async (req, res) => {
  const { userId, password, address } = req.body;
  if (!userId || !password || !address) {
    return res.status(400).json({ message: "userId, password, address 필요" });
  }
  try {
    const u = await pool.query("SELECT password_hash FROM users WHERE user_id=$1", [userId]);
    const user = u.rows[0];
    if (!user) return res.status(401).json({ message: "인증 실패" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: "인증 실패" });

    await pool.query(
      "DELETE FROM wallets WHERE user_id=$1 AND address=$2",
      [userId, address]
    );
    res.json({ message: "지갑 삭제 완료" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "지갑 삭제 실패" });
  }
});

// Vercel 서버리스 함수 핸들러 (Vercel 사용 시)
module.exports = (req, res) => app(req, res);

// 로컬 서버로도 실행하고 싶다면 아래 주석 해제
// const PORT = process.env.PORT || 5000;
// app.listen(PORT, () => console.log(`Server on http://localhost:${PORT}`));
