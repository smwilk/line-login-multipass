const passport = require('passport');
const LineStrategy = require('passport-line-auth').Strategy;
const express = require('express');
const app = express();
const User = require('./models/user'); // assuming you have a User model defined in models/user.js
require('dotenv').config();

app.get('/auth/line', passport.authenticate('line'));

app.get('/auth/line/callback',
    passport.authenticate('line', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
    });

passport.use(new LineStrategy({
    channelID: process.env.LINE_CHANNEL_ID,
    channelSecret: process.env.LINE_CHANNEL_SECRET,
    callbackURL: 'http://yourwebsite.com/auth/line/callback',
    scope: ['profile', 'openid', 'email'],
    botPrompt: 'normal'
},
    function (accessToken, refreshToken, params, profile, cb) {
        User.findOrCreate({ lineId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));