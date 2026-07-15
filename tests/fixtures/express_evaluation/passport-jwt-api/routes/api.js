const express = require("express");
const passport = require("passport");
const router = express.Router();

router.post("/signup", handler);
router.get("/signout", passport.authenticate("jwt", { session: false }), handler);
router.post("/book", passport.authenticate("jwt", { session: false }), handler);
router.get("/book", passport.authenticate("jwt", { session: false }), handler);
module.exports = router;
