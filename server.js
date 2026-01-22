import express from "express";
import cors from "cors";
import Database from "better-sqlite3";
import crypto from "crypto";

const app = express();

// باش req.ip يجيب IP الحقيقي وراء Render/Proxy
app.set("trust proxy", 1);

app.use(express.json());

/**
 * مهم: إلا بغيتي Cookie يخدم cross-site (LP domain مختلف على server)
 * خاص: cors credentials + origin محدد
 *
 * دير ENV فـ Render:
 * ALLOWED_ORIGINS=https://shtek.shop,https://www.shtek.shop
 */
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // Postman/curl
      if (ALLOWED_ORIGINS.length === 0) return cb(null, true); // للتجربة فقط
      return cb(null, ALLOWED_ORIGINS.includes(origin));
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);

app.options("*", cors());

// DB
const DB_PATH = process.env.DB_PATH || "db.sqlite";
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

// جدول عام كيخزن أي key (ip / cid / fp)
db.exec(`
  CREATE TABLE IF NOT EXISTS blocks (
    k TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
  );
`);

const TTL_HOURS = Number(process.env.TTL_HOURS || 24);
const TTL_MS = TTL_HOURS * 60 * 60 * 1000;

function cleanupExpired() {
  db.prepare("DELETE FROM blocks WHERE expires_at <= ?").run(Date.now());
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").forEach((p) => {
    const s = p.trim();
    if (!s) return;
    const i = s.indexOf("=");
    if (i === -1) return;
    out[s.slice(0, i)] = decodeURIComponent(s.slice(i + 1));
  });
  return out;
}

function ensureCookieId(req, res) {
  const cookies = parseCookies(req);
  let cid = cookies["sidox_cid"];
  if (!cid) {
    cid = crypto.randomBytes(16).toString("hex");

    // IMPORTANT: SameSite=None + Secure باش يخدم cross-site
    // Max-Age 30 يوم غير للتعريف، TTL الحقيقي هو DB (24h)
    res.setHeader(
      "Set-Cookie",
      `sidox_cid=${cid}; Path=/; Max-Age=${60 * 60 * 24 * 30}; SameSite=None; Secure`
    );
  }
  return cid;
}

function getClientIp(req) {
  // trust proxy كيعاون، ولكن نزيدو x-forwarded-for
  const xff = req.headers["x-forwarded-for"];
  let ip = "";

  if (xff && typeof xff === "string") ip = xff.split(",")[0].trim();
  else ip = req.ip || "";

  if (ip.startsWith("::ffff:")) ip = ip.replace("::ffff:", "");
  return ip;
}

function makeKey(type, value) {
  if (!value) return null;
  return `${type}:${value}`;
}

function isBlocked(keys) {
  const now = Date.now();
  const stmt = db.prepare("SELECT expires_at FROM blocks WHERE k = ?");

  for (const k of keys) {
    if (!k) continue;
    const row = stmt.get(k);
    if (row && row.expires_at > now) {
      return { blocked: true, expiresAt: row.expires_at, hit: k };
    }
  }
  return { blocked: false };
}

function markBlocked(items) {
  const now = Date.now();
  const expiresAt = now + TTL_MS;

  const stmt = db.prepare(`
    INSERT INTO blocks (k, type, expires_at, last_seen)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(k) DO UPDATE SET
      expires_at = excluded.expires_at,
      last_seen  = excluded.last_seen
  `);

  for (const it of items) {
    if (!it?.k) continue;
    stmt.run(it.k, it.type, expiresAt, now);
  }

  return { ok: true, expiresAt };
}

/**
 * ✅ /check: كيشوف IP + CookieID + Fingerprint(optional)
 * إذا أي واحد فيهم blocked → blocked
 */
app.post("/check", (req, res) => {
  cleanupExpired();

  const ip = getClientIp(req);
  const cid = ensureCookieId(req, res);

  const fpRaw = req.body?.fingerprint;
  const fp = typeof fpRaw === "string" && fpRaw.length >= 10 ? fpRaw : null;

  const r = isBlocked([makeKey("ip", ip), makeKey("cid", cid), makeKey("fp", fp)]);

  if (r.blocked) {
    const remainingMs = r.expiresAt - Date.now();
    return res.json({
      blocked: true,
      remainingSeconds: Math.max(1, Math.ceil(remainingMs / 1000)),
      hit: r.hit,
    });
  }

  return res.json({ blocked: false });
});

/**
 * ✅ /mark: كتسجّل block 24h على IP + CookieID + Fingerprint(optional)
 */
app.post("/mark", (req, res) => {
  cleanupExpired();

  const ip = getClientIp(req);
  const cid = ensureCookieId(req, res);

  const fpRaw = req.body?.fingerprint;
  const fp = typeof fpRaw === "string" && fpRaw.length >= 10 ? fpRaw : null;

  const result = markBlocked([
    { k: makeKey("ip", ip), type: "ip" },
    { k: makeKey("cid", cid), type: "cid" },
    { k: makeKey("fp", fp), type: "fp" },
  ]);

  return res.json({ ...result });
});

app.get("/", (req, res) => res.send(`Anti-fake server running ✅ (TTL=${TTL_HOURS}h)`));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Listening on", PORT));
