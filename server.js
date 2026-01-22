// server.js
import express from "express";
import cors from "cors";
import Database from "better-sqlite3";
import crypto from "crypto";

const app = express();

// Needed on Render / proxies to get real client IP
app.set("trust proxy", 1);

app.use(express.json());

// ====== CORS (IMPORTANT for cookies) ======
// Best practice: set STORE_ORIGIN to your store domain, e.g. https://shtek.shop
// If you leave it empty, it will reflect the request origin (less strict).
const STORE_ORIGIN = process.env.STORE_ORIGIN || "";

app.use(
  cors({
    origin: (origin, cb) => {
      // allow same-origin / server-to-server / curl with no origin
      if (!origin) return cb(null, true);

      if (!STORE_ORIGIN) return cb(null, true); // reflect any origin (not strict)

      // strict mode
      if (origin === STORE_ORIGIN) return cb(null, true);
      return cb(new Error("CORS blocked: origin not allowed"));
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);

app.options("*", cors());

// ====== SQLite ======
const db = new Database("db.sqlite");
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS blocks (
    key TEXT PRIMARY KEY,
    type TEXT NOT NULL,        -- "ip" or "cid"
    expires_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
  );
`);

function cleanupExpired() {
  const now = Date.now();
  db.prepare("DELETE FROM blocks WHERE expires_at <= ?").run(now);
}

// ====== Helpers ======
function getClientIp(req) {
  let ip = req.ip || "";

  // remove IPv6 mapping prefix
  if (ip.startsWith("::ffff:")) ip = ip.replace("::ffff:", "");

  // if still empty, try x-forwarded-for (first IP)
  const xff = req.headers["x-forwarded-for"];
  if (!ip && typeof xff === "string") ip = xff.split(",")[0].trim();

  return ip || "";
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").forEach((part) => {
    const [k, ...v] = part.trim().split("=");
    if (!k) return;
    out[k] = decodeURIComponent(v.join("=") || "");
  });
  return out;
}

function ensureCookieId(req, res) {
  const cookies = parseCookies(req);
  let cid = cookies["sidox_cid"];

  if (!cid) {
    cid = crypto.randomBytes(16).toString("hex");

    // Cross-site cookie rules:
    // - SameSite=None; Secure is required
    // - Path=/ so it works everywhere
    // - Max-Age 30 days (cookie lifetime), but the block itself is 24h in DB
    res.setHeader("Set-Cookie", [
      `sidox_cid=${cid}; Path=/; Max-Age=${60 * 60 * 24 * 30}; SameSite=None; Secure`,
    ]);
  }

  return cid;
}

function isBlocked(type, key) {
  if (!key) return null;
  const row = db
    .prepare("SELECT expires_at FROM blocks WHERE type = ? AND key = ?")
    .get(type, key);

  if (row && row.expires_at > Date.now()) {
    const remainingMs = row.expires_at - Date.now();
    return Math.ceil(remainingMs / 1000);
  }
  return null;
}

function markBlocked(type, key, ttlMs) {
  const now = Date.now();
  const expiresAt = now + ttlMs;

  db.prepare(`
    INSERT INTO blocks (key, type, expires_at, last_seen)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET
      type = excluded.type,
      expires_at = excluded.expires_at,
      last_seen = excluded.last_seen
  `).run(key, type, expiresAt, now);

  return expiresAt;
}

// ====== Routes ======
app.get("/", (req, res) => res.send("Anti-fake server running ✅"));

// CHECK (LP): if blocked by IP OR by Cookie ID => blocked
app.post("/check", (req, res) => {
  cleanupExpired();

  const ip = getClientIp(req);
  const cid = ensureCookieId(req, res);

  const ipRemaining = isBlocked("ip", ip);
  const cidRemaining = isBlocked("cid", cid);

  if (ipRemaining || cidRemaining) {
    return res.json({
      blocked: true,
      remainingSeconds: Math.max(ipRemaining || 0, cidRemaining || 0),
      by: ipRemaining ? "ip" : "cid",
    });
  }

  return res.json({ blocked: false });
});

// MARK (THANK YOU): mark IP + Cookie for 24h
app.post("/mark", (req, res) => {
  cleanupExpired();

  const ip = getClientIp(req);
  const cid = ensureCookieId(req, res);

  const TTL_24H = 24 * 60 * 60 * 1000;

  const result = {
    ok: true,
    marked: [],
    expiresAt: null,
  };

  let expiresAt = null;

  if (ip) {
    expiresAt = markBlocked("ip", ip, TTL_24H);
    result.marked.push("ip");
  }

  if (cid) {
    expiresAt = markBlocked("cid", cid, TTL_24H);
    result.marked.push("cid");
  }

  result.expiresAt = expiresAt;
  return res.json(result);
});

// Optional: debugging endpoint (remove if you want)
app.post("/whoami", (req, res) => {
  const ip = getClientIp(req);
  const cid = ensureCookieId(req, res);
  res.json({ ip, cid });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Listening on", PORT));
