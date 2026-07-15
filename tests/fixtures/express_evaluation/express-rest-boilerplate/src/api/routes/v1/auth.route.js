const express = require("express");
const router = express.Router();
const validate = require("validate");

router.post("/login", validate(login), handler);
module.exports = router;
