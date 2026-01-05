const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const router = express.Router();
const User = require('../models/User');

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;

// Helper to sign JWT
const signToken = (user) => {
    return jwt.sign(
        {
            id: user._id || user.id,
            username: user.username,
            email: user.email,
            avatar: user.avatar,
            discordId: user.discordId
        },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
    );
};

// --- Traditional Auth (Email/Gmail) ---

// Registration
router.post('/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "Email and password required" });

    try {
        const existing = await User.findOne({ email });
        if (existing) return res.status(400).json({ success: false, message: "Email already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        // Use part of email as initial username if not provided
        const username = email.split('@')[0];
        const newUser = new User({ email, username, password: hashedPassword });
        await newUser.save();

        const token = signToken(newUser);
        res.cookie('auth_token', token, { httpOnly: false, secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.json({ success: true, message: "Registration successful" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Registration failed", error: err.message });
    }
});

// Login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "Credentials required" });

    try {
        const user = await User.findOne({ email });
        if (!user || !user.password) return res.status(401).json({ success: false, message: "Invalid credentials" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ success: false, message: "Invalid credentials" });

        const token = signToken(user);
        res.cookie('auth_token', token, { httpOnly: false, secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.json({ success: true, message: "Login successful" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Login failed" });
    }
});

// --- Discord Auth ---

router.get('/discord', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify email`;
    res.redirect(url);
});

router.get('/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send('No code provided');

    try {
        const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: REDIRECT_URI,
        }).toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const { access_token } = tokenResponse.data;
        const userResponse = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        const discordUser = userResponse.data;

        // Unify with User model
        let dbUser = await User.findOne({ discordId: discordUser.id });
        if (!dbUser) {
            // Check if user with same email exists
            if (discordUser.email) {
                dbUser = await User.findOne({ email: discordUser.email });
            }

            if (!dbUser) {
                dbUser = new User({
                    username: discordUser.username,
                    email: discordUser.email,
                    discordId: discordUser.id,
                    avatar: discordUser.avatar
                });
            } else {
                // Link discord
                dbUser.discordId = discordUser.id;
                dbUser.avatar = discordUser.avatar;
            }
            await dbUser.save();
        } else {
            // Update profile
            dbUser.avatar = discordUser.avatar;
            dbUser.username = discordUser.username;
            if (discordUser.email) dbUser.email = discordUser.email;
            await dbUser.save();
        }

        const token = signToken(dbUser);
        res.cookie('auth_token', token, { httpOnly: false, secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.redirect(`${process.env.FRONTEND_URL}/dashboard.html`);
    } catch (error) {
        console.error('OAuth Error:', error.response?.data || error.message);
        res.status(500).send('Authentication failed');
    }
});

router.get('/me', (req, res) => {
    const token = req.cookies.auth_token;
    if (!token) return res.status(401).json({ success: false });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        res.json({ success: true, user: decoded });
    } catch (err) {
        res.status(401).json({ success: false });
    }
});

module.exports = router;
