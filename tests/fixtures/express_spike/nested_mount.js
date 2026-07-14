const express = require("express");
const app = express();
const parent = express.Router();
const child = express.Router();
app.use("/api", parent);
parent.use("/v1", child);
child.get("/users", handler);
