const express = require("express");
const app = express();
const router = express.Router();
router.get("/before", handler);
router.use(requireAuth);
router.get("/after", handler);
