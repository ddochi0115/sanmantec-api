// 필요한 모듈들을 가져옵니다.
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const app = express();
const port = 5000;

// CORS & JSON
app.use(cors());
app.use(express.json());

// ★★★★★ PostgreSQL 데이터베이스 연결 정보 설정 ★★★★★
const pool = new Pool({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT,
});
// 데이터베이스 연결 테스트
pool.connect((err, client, release) => {
  if (err) {
    return console.error("데이터베이스 연결 실패:", err.stack);
  }
  console.log("데이터베이스 연결 성공");
  release();
});

// 회원가입
app.post("/signup", async (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) {
    return res.status(400).json({ message: "입력값 확인 필요" });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const query = "INSERT INTO users (user_id, password_hash) VALUES ($1, $2) RETURNING id";
    await pool.query(query, [userId, hash]);
    console.log("새로운 사용자 가입:", userId);
    res.status(201).json({ message: "회원가입이 완료되었습니다." });
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
  const query = "SELECT * FROM users WHERE user_id = $1";
  const result = await pool.query(query, [userId]);
  const row = result.rows[0];

  if (!row) {
    return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });
  }
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) {
    return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });
  }
  console.log("로그인 성공:", userId);
  res.status(200).json({ message: "로그인에 성공했습니다.", user: { userId: row.user_id } });
});

// 서버 실행
app.listen(port, () => {
  console.log(`서버가 http://localhost:${port} 에서 실행되었습니다.`);
});