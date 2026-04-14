// Fixture: an Express app with a mix of guarded and unguarded routes.
const express = require("express");
const app = express();

// EXPOSED: no auth on a sensitive admin route.
app.post("/api/admin/delete-user", (req, res) => {
  res.json({ ok: true });
});

// PROTECTED: inline auth middleware present on the same line.
app.get("/api/profile", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// PUBLIC: health endpoint is intentionally open.
app.get("/health", (req, res) => res.send("ok"));

module.exports = app;
