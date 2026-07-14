const express = require("express");
const app = express();
app.get("/account", requireAuth, audit, handler);
authmap.public("/health");
app.get("/health", handler);
