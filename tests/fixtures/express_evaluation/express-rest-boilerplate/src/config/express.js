const express = require("express");
const routes = require("../api/routes/v1");
const app = express();

app.use("/v1", routes);
