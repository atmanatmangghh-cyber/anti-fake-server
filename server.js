import express from "express";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

const BLOCK_HOURS = 24;

// تخزين مؤقت فالرام (نسخة بسيطة)
const blockedVisitors = new Map();

// health check
app.get("/", (req, res) => {
  res.send("Anti-fake server running ✅");
});

// check visitor
app.post("/check", (req, res) => {
  const { visitorId } = req.body;

  if (!visitorId) {
    return res.status(400).json({ error: "visitorId required" });
  }

  const record = blockedVisitors.get(visitorId);

  if (record && Date.now() < record) {
    return res.json({
      blocked: true,
      remainingMs: record - Date.now()
    });
  }

  res.json({ blocked: false });
});

// mark order completed
app.post("/complete", (req, res) => {
  const { visitorId } = req.body;

  if (!visitorId) {
    return res.status(400).json({ error: "visitorId required" });
  }

  const blockUntil = Date.now() + BLOCK_HOURS * 60 * 60 * 1000;
  blockedVisitors.set(visitorId, blockUntil);

  res.json({ success: true, blockUntil });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
