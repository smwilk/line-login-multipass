// Import necessary modules
const express = require('express');
const passport = require('passport');
const dotenv = require('dotenv');
const LineStrategy = require('passport-line-auth').Strategy;
const session = require('express-session');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Load environment variables
dotenv.config();

// Create a new Express application
const app = express();

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// Use express-session middleware for managing user sessions
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

// Initialize Passport.js for authentication
app.use(passport.initialize());
app.use(passport.session());

// Function to generate a Shopify Multipass token
function generateMultipassToken(customerData) {
    const multipassSecret = process.env.SHOPIFY_MULTIPASS_SECRET;
    const keyMaterial = crypto.createHash('sha256').update(multipassSecret).digest();
    const encryptionKey = keyMaterial.slice(0, 16);
    const signatureKey = keyMaterial.slice(16, 32);

    const data = Buffer.from(JSON.stringify(customerData), 'utf-8');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-cbc', encryptionKey, iv);
    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
    const token = Buffer.concat([iv, ciphertext]);
    const signature = crypto.createHmac('sha256', signatureKey).update(token).digest();

    return Buffer.concat([token, signature]).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Set up the LINE Login strategy with Passport.js
passport.use(new LineStrategy({
    channelID: process.env.LINE_CHANNEL_ID,
    channelSecret: process.env.LINE_CHANNEL_SECRET,
    callbackURL: 'https://shopify-line-login.onrender.com/auth/line/callback',
    scope: ['profile', 'openid', 'email'],
    botPrompt: 'normal'
},
    (accessToken, refreshToken, params, profile, cb) => {
        // Decode the id_token to get the user's email
        const decodedIdToken = jwt.decode(params.id_token);
        const email = decodedIdToken ? decodedIdToken.email : 'No email address provided';

        // Add the email to the user's profile
        profile.email = email;

        return cb(null, profile);
    }));

// Define how Passport.js should serialize and deserialize user instances to and from the session
passport.serializeUser((user, cb) => {
    cb(null, user);
});

passport.deserializeUser((obj, cb) => {
    cb(null, obj);
});

// Define routes
app.get('/auth/line', passport.authenticate('line'));

app.get('/auth/line/callback',
    passport.authenticate('line', { failureRedirect: '/login-failed' }),
    (req, res) => {
        const customerData = {
            email: req.user.email,
            created_at: new Date().toISOString(),
            // Add other customer information here
        };
        console.log('customerData', customerData);
        const multipassToken = generateMultipassToken(customerData);
        res.redirect(`https://${process.env.SHOPIFY_STORE_DOMAIN}/account/login/multipass/${multipassToken}`);
    });

app.get('/login', (req, res) => {
    res.send(`Successfully logged in, thanks ${req.user.displayName}. Your email is ${req.user.email}`);
});

app.get('/login-failed', (req, res) => {
    res.send('Login failed');
});

app.get('/consent', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'consent.html'));
});

// Start the server
app.listen(5656, () => {
    console.log("App listening on port 5656!");
});