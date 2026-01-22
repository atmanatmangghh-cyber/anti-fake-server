import express from "express";
import cors from "cors";
import Database from "better-sqlite3";

const app = express();

// مهم فـ Render/Proxies باش req.ip يجيب IP الحقيقي
app.set("trust proxy", 1);

app.use(express.json());

// بدّل هاد الدومين لدومين الستور ديالك باش CORS يكون مضبوط
app.use(
  cors({
    origin: true, // إلى بغيتي تشددها: ["https://YOUR-DOMAIN.com"]
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);

const db = new Database("db.sqlite");
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS ip_blocks (
    ip TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
  );
`);

function getClientIp(req) {
  // Express مع trust proxy كيعطيك req.ip مزيان
  let ip = req.ip || "";
  // نحيّد prefix ديال IPv6 mapping
  if (ip.startsWith("::ffff:")) ip = ip.replace("::ffff:", "");
  return ip;
}

function cleanupExpired() {
  const now = Date.now();
  db.prepare("DELETE FROM ip_blocks WHERE expires_at <= ?").run(now);
}

// Check IP
app.post("/check-ip", (req, res) => {
  cleanupExpired();
  const ip = getClientIp(req);

  if (!ip) return res.json({ blocked: false, reason: "no_ip" });

  const row = db.prepare("SELECT expires_at FROM ip_blocks WHERE ip = ?").get(ip);

  if (row && row.expires_at > Date.now()) {
    const remainingMs = row.expires_at - Date.now();
    return res.json({ blocked: true, remainingSeconds: Math.ceil(remainingMs / 1000) });
  }

  return res.json({ blocked: false });
});

// Mark IP for 24h
app.post("/mark-ip", (req, res) => {
  cleanupExpired();
  const ip = getClientIp(req);
  if (!ip) return res.json({ ok: false, reason: "no_ip" });

  const now = Date.now();
  const expiresAt = now + 24 * 60 * 60 * 1000;

  db.prepare(`
    INSERT INTO ip_blocks (ip, expires_at, last_seen)
    VALUES (?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET
      expires_at = excluded.expires_at,
      last_seen = excluded.last_seen
  `).run(ip, expiresAt, now);

  res.json({ ok: true, ip, expiresAt });
});

app.get("/", (req, res) => res.send("Anti-fake server running ✅"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Listening on", PORT));
