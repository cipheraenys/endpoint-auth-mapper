const express = require("express");
const router = express.Router();
const { authorize } = require("../../middlewares/auth");

router.get("/profile", authorize(), handler);
module.exports = router;
