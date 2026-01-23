import express from "express";
import cors from "cors";
import Database from "better-sqlite3";
import crypto from "crypto";

const app = express();
app.set("trust proxy", 1);
app.use(express.json());

// CORS (خليها origin:true مؤقتاً حتى تخدم، ومن بعد شددها)
app.use(
  cors({
    origin: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);
app.options("*", cors());

// DB
const DB_PATH = process.env.DB_PATH || "db.sqlite";
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS blocks (
    cid TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
  );
`);

const TTL_HOURS = Number(process.env.TTL_HOURS || 24);
const TTL_MS = TTL_HOURS * 60 * 60 * 1000;

// ===== Token Sign/Verify =====
const TOKEN_SECRET = process.env.TOKEN_SECRET || "CHANGE_ME_NOW_LONG_SECRET";

function hmac(str) {
  return crypto.createHmac("sha256", TOKEN_SECRET).update(str).digest("hex");
}

function makeToken(cid) {
  const ts = Date.now();
  const payload = `${cid}.${ts}`;
  const sig = hmac(payload);
  return `${payload}.${sig}`; // cid.ts.sig
}

function verifyToken(token, cid) {
  if (!token || typeof token !== "string") return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;

  const [tCid, tTs, tSig] = parts;
  if (tCid !== cid) return false;

  const payload = `${tCid}.${tTs}`;
  const sig = hmac(payload);

  // timing safe
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(tSig));
  } catch {
    return false;
  }
}

function cleanupExpired() {
  db.prepare("DELETE FROM blocks WHERE expires_at <= ?").run(Date.now());
}

// ====== ISSUE TOKEN ======
app.post("/issue", (req, res) => {
  const cid = req.body?.cid;
  if (!cid || typeof cid !== "string" || cid.length < 6) {
    return res.status(400).json({ ok: false, reason: "bad_cid" });
  }
  return res.json({ ok: true, token: makeToken(cid) });
});

// ====== CHECK ======
app.post("/check", (req, res) => {
  cleanupExpired();

  const cid = req.body?.cid;
  const token = req.body?.token;

  if (!cid || !token) return res.status(400).json({ blocked: false, reason: "missing" });
  if (!verifyToken(token, cid)) return res.status(403).json({ blocked: false, reason: "bad_token" });

  const row = db.prepare("SELECT expires_at FROM blocks WHERE cid = ?").get(cid);

  if (row && row.expires_at > Date.now()) {
    const remainingMs = row.expires_at - Date.now();
    return res.json({
      blocked: true,
      remainingSeconds: Math.ceil(remainingMs / 1000),
    });
  }

  return res.json({ blocked: false });
});

// ====== MARK (بعد نجاح الطلب فـ Thank You) ======
app.post("/mark", (req, res) => {
  cleanupExpired();

  const cid = req.body?.cid;
  const token = req.body?.token;

  if (!cid || !token) return res.status(400).json({ ok: false, reason: "missing" });
  if (!verifyToken(token, cid)) return res.status(403).json({ ok: false, reason: "bad_token" });

  const now = Date.now();
  const expiresAt = now + TTL_MS;

  db.prepare(`
    INSERT INTO blocks (cid, expires_at, last_seen)
    VALUES (?, ?, ?)
    ON CONFLICT(cid) DO UPDATE SET
      expires_at = excluded.expires_at,
      last_seen  = excluded.last_seen
  `).run(cid, expiresAt, now);

  return res.json({ ok: true, expiresAt });
});

app.get("/", (req, res) => res.send(`Anti-fake server ✅ TTL=${TTL_HOURS}h`));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Listening on", PORT));
