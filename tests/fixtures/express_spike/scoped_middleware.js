const express = require("express");
const app = express();
const protectedRouter = express.Router();
const openRouter = express.Router();
protectedRouter.use(requireAuth);
protectedRouter.get("/account", handler);
openRouter.get("/status", handler);
