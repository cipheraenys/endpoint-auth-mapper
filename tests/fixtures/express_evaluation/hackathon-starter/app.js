const express = require("express");
const passport = require("passport");
const passportConfig = require("./passport-config");
const app = express();

app.get("/", home);
app.get("/account", passportConfig.isAuthenticated, account);
app.get("/auth/github", passport.authenticate("github"), callback);
