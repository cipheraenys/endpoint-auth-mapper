const express = require("express");
const app = express();
const routerA = express.Router();
const routerB = express.Router();
routerA.use(requireAuth);
routerB.get("/other", handler);
