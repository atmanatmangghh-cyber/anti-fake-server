import express from "express";
import cors from "cors";
import Database from "better-sqlite3";
import crypto from "crypto";

const app = express();
app.set("trust proxy", 1);

app.use(express.json());

app.use(
  cors({
    origin: true,
    credentials: true, // مهم للكوكيز
  })
);

const db = new Database("db.sqlite");
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    cookie_id TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
`);

function cleanupExpired() {
  db.prepare(`DELETE FROM blocks WHERE expires_at <= ?`).run(Date.now());
}

function getClientIp(req) {
  let ip = req.ip || "";
  if (ip.startsWith("::ffff:")) ip = ip.replace("::ffff:", "");
  return ip;
}

function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) return {};
  return Object.fromEntries(
    header.split(";").map(c => {
      const [k, ...v] = c.trim().split("=");
      return [k, decodeURIComponent(v.join("="))];
    })
  );
}

function generateId() {
  return crypto.randomBytes(16).toString("hex");
}

/* ================= CHECK ================= */
app.post("/check", (req, res) => {
  cleanupExpired();

  const ip = getClientIp(req);
  const cookies = parseCookies(req);
  const cookieId = cookies.af_id;

  const now = Date.now();

  const row = db.prepare(`
    SELECT * FROM blocks
    WHERE (ip = ? OR cookie_id = ?)
      AND expires_at > ?
    LIMIT 1
  `).get(ip, cookieId || "", now);

  if (row) {
    return res.json({
      blocked: true,
      remainingSeconds: Math.ceil((row.expires_at - now) / 1000),
    });
  }

  return res.json({ blocked: false });
});

/* ================= MARK ================= */
app.post("/mark", (req, res) => {
  cleanupExpired();

  const ip = getClientIp(req);
  const cookies = parseCookies(req);

  let cookieId = cookies.af_id;
  if (!cookieId) cookieId = generateId();

  const now = Date.now();
  const expiresAt = now + 24 * 60 * 60 * 1000;

  db.prepare(`
    INSERT INTO blocks (ip, cookie_id, expires_at, created_at)
    VALUES (?, ?, ?, ?)
  `).run(ip, cookieId, expiresAt, now);

  res.setHeader(
    "Set-Cookie",
    `af_id=${cookieId}; Max-Age=86400; Path=/; SameSite=Lax`
  );

  res.json({ ok: true });
});

app.get("/", (_, res) => res.send("Anti-fake server running ✅"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on", PORT));
