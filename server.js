const fs = require("fs");
const path = require("path");
const https = require("https");
const express = require("express");
const helmet = require("helmet");
const passport = require("passport");
const { Strategy } = require("passport-google-oauth20");
const cookieSession = require("cookie-session");
require("dotenv").config();

const PORT = 3000;
const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
};

const AUTH_OPTIONS = {
  callbackURL: "/auth/google/callback",
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

function verifyCallback(accessToken, refreshToken, profile, done) {
  // console.log("Google Profile: ", profile);
  done(null, profile); //(OnError function, userData for successfully authenticated user)
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

//save the session to the cookie
passport.serializeUser((user, done) => {
  done(null, { id: user.id, email: user.emails[0].value });
}); //user: serialize user, Done: callback for asynchronous if needed

//read the session from the cookie
passport.deserializeUser((obj, done) => {
  console.log("obj: ", obj);
  done(null, obj);
});
const app = express();

app.use(helmet());
app.use(
  cookieSession({
    name: "session",
    maxAge: 24 * 60 * 60 * 1000,
    keys: [AUTH_OPTIONS.COOKIE_KEY_1, AUTH_OPTIONS.COOKIE_KEY_2],
  })
);
app.use(passport.initialize()); //middleware to setup passport session, serialize user session
app.use(passport.session()); //authenticate the session that being sent to the server
function checkLoggedIn(req, res, next) {
  const isLoggedIn = req.isAuthenticated() && req.user;
  console.log("curr user: ", isLoggedIn);
  if (!isLoggedIn) {
    return res.status(410).json({
      error: "You must log in!",
    });
  }
  next();
}

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["email"],
  })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/failure",
    successRedirect: "/",
    session: true,
  }),
  (req, res) => {
    // res.redirect()
    console.log("google called us back!");
  }
);

app.get("/auth/logout", (req, res) => {
  req.logOut(); //removes req.user & celars any logged in session
  return res.redirect("/");
});

app.get("/secret", checkLoggedIn, (req, res) => {
  return res.send("Your personal secret value is 42!");
});

app.get("/failure", (req, res) => {
  res.status(200).send("failed to login");
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

https
  .createServer(
    {
      key: fs.readFileSync("key.pem"),
      cert: fs.readFileSync("cert.pem"),
    },
    app
  )
  .listen(PORT, () => {
    console.log(`Listening on port ${PORT}...`);
  });

//express-session: server-side session
//| better security protection, need DB, eat more space for the server to handle the DB

//cookie-session: client-side session
//| better scalability, no DB required, but browser limiting the cookies data limit (4096 bytes) & maybe not 100% secure (maybe someone can modify it).
