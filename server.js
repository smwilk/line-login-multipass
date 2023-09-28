const express = require('express');
const passport = require('passport');
const dotenv = require('dotenv');
dotenv.config();
const LineStrategy = require('passport-line-auth').Strategy;
const session = require('express-session');

const app = express();

// Use express-session middleware
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

// Initialize passport
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LineStrategy({
    channelID: process.env.LINE_CHANNEL_ID,
    channelSecret: process.env.LINE_CHANNEL_SECRET,
    callbackURL: 'https://shopify-line-login.onrender.com/auth/line/callback',
    scope: ['profile', 'openid', 'email'],
    botPrompt: 'normal'
},
    function (accessToken, refreshToken, params, profile, cb) {
        return cb(null, profile);
    }));

passport.serializeUser(function (user, cb) {
    cb(null, user);
});

passport.deserializeUser(function (obj, cb) {
    cb(null, obj);
});

app.get('/auth/line', passport.authenticate('line'));

app.get('/auth/line/callback',
    passport.authenticate('line', { failureRedirect: '/login-failed', successRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.send(`Hello ${req.user.displayName}, you have successfully logged in!`);
    });

app.get('/login', function (req, res) {
    res.send(`Successfully logged in, thanks ${req.user.displayName}`);
});

app.get('/login-failed', function (req, res) {
    res.send('Login failed');
});

app.listen(5656, function () {
    console.log("App listening on port 5656!");
});