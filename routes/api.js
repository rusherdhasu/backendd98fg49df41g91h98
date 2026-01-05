const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();
const Panel = require('../models/Panel');
const License = require('../models/License');
const HWIDAccess = require('../models/HWIDAccess');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// MiddleWare to verify User via JWT
const verifyUser = (req, res, next) => {
    const token = req.cookies.auth_token || req.headers['authorization'];
    if (!token) return res.status(401).json({ success: false, message: "Login required" });

    try {
        const decoded = jwt.verify(token.startsWith('Bearer ') ? token.slice(7) : token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: "Invalid session" });
    }
};

// --- Panel Routes ---

router.get('/panels', verifyUser, async (req, res) => {
    try {
        // Search by internal MongoDB ID OR Discord ID if linked
        const query = {
            $or: [{ ownerId: req.user.id }]
        };

        if (req.user.discordId) {
            query.$or.push({ ownerId: req.user.discordId });
        }

        const panels = await Panel.find(query);
        res.json({ success: true, panels });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error" });
    }
});

router.post('/panels', verifyUser, async (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ success: false, message: "Name required" });

    try {
        const secret = crypto.randomBytes(16).toString('hex');
        // Prefer discordId for ownerId if available to keep it consistent with bot
        const ownerId = req.user.discordId || req.user.id;
        const newPanel = new Panel({ ownerId, name, secret });
        await newPanel.save();
        res.json({ success: true, panel: newPanel });
    } catch (err) {
        res.status(500).json({ success: false, message: "Panel name exists or server error" });
    }
});

router.patch('/panels/:id', verifyUser, async (req, res) => {
    try {
        const panel = await Panel.findOneAndUpdate(
            { _id: req.params.id, ownerId: req.user.id },
            { $set: req.body },
            { new: true }
        );
        if (!panel) return res.status(404).json({ success: false, message: "Panel not found" });
        res.json({ success: true, panel });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error" });
    }
});

router.delete('/panels/:id', verifyUser, async (req, res) => {
    try {
        const panel = await Panel.findOneAndDelete({ _id: req.params.id, ownerId: req.user.id });
        if (!panel) return res.status(404).json({ success: false, message: "Panel not found" });
        // Cleanup associated data
        await License.deleteMany({ panelId: panel._id });
        await HWIDAccess.deleteMany({ panelId: panel._id });
        res.json({ success: true, message: "Panel and associated data deleted" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// --- User Management (License) Routes ---

router.get('/users/:panelId', verifyUser, async (req, res) => {
    try {
        const { panelId } = req.params;
        console.log(`[API] Requested users for panel: ${panelId}`);

        if (!mongoose.Types.ObjectId.isValid(panelId)) {
            console.warn(`[API] Invalid panelId format: ${panelId}`);
            return res.status(400).json({ success: false, message: "Invalid panel ID format" });
        }

        const users = await License.find({ panelId }).lean();
        console.log(`[API] Successfully found ${users.length} users for panel ${panelId}`);
        res.json({ success: true, users });
    } catch (err) {
        console.error('[API] GET Users ERROR STACK:', err.stack);
        res.status(500).json({
            success: false,
            message: "Server encountered an error fetching users",
            details: err.message
        });
    }
});

router.post('/users/:panelId', verifyUser, async (req, res) => {
    const { username, password, expiryDays, status } = req.body;
    if (!username) return res.status(400).json({ success: false, message: "Username required" });

    try {
        const { panelId } = req.params;
        if (!mongoose.Types.ObjectId.isValid(panelId)) {
            return res.status(400).json({ success: false, message: "Invalid panel ID format" });
        }

        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + (parseInt(expiryDays) || 30));

        const newUser = new License({
            username,
            password: password || "",
            panelId: panelId,
            expiryDate,
            status: status || 'active'
        });
        await newUser.save();
        res.json({ success: true, user: newUser });
    } catch (err) {
        console.error('[API] POST User Error:', err);
        res.status(500).json({ success: false, message: "Server error: " + err.message });
    }
});

router.patch('/users/:userId', verifyUser, async (req, res) => {
    try {
        const { userId } = req.params;
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ success: false, message: "Invalid user ID" });
        }
        const user = await License.findByIdAndUpdate(
            userId,
            { $set: req.body },
            { new: true }
        );
        res.json({ success: true, user });
    } catch (err) {
        console.error('[API] PATCH User Error:', err);
        res.status(500).json({ success: false, message: "Server error: " + err.message });
    }
});

router.delete('/users/:userId', verifyUser, async (req, res) => {
    try {
        const { userId } = req.params;
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ success: false, message: "Invalid user ID" });
        }
        await License.findByIdAndDelete(userId);
        res.json({ success: true, message: "User deleted" });
    } catch (err) {
        console.error('[API] DELETE User Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// --- HWID Access Routes ---

router.get('/hwid/:panelId', verifyUser, async (req, res) => {
    try {
        const { panelId } = req.params;
        if (!mongoose.Types.ObjectId.isValid(panelId)) {
            return res.status(400).json({ success: false, message: "Invalid panel ID" });
        }
        const access = await HWIDAccess.find({ panelId });
        res.json({ success: true, access });
    } catch (err) {
        console.error('[API] GET HWID Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

router.post('/hwid/:panelId', verifyUser, async (req, res) => {
    const { hwid, name, expiryDays } = req.body;
    if (!hwid || !name) return res.status(400).json({ success: false, message: "HWID and Name required" });

    try {
        const { panelId } = req.params;
        if (!mongoose.Types.ObjectId.isValid(panelId)) {
            return res.status(400).json({ success: false, message: "Invalid panel ID" });
        }
        let expiryDate = null;
        if (expiryDays) {
            expiryDate = new Date();
            expiryDate.setDate(expiryDate.getDate() + parseInt(expiryDays));
        }

        const newAccess = new HWIDAccess({
            panelId: panelId,
            hwid,
            name,
            expiryDate
        });
        await newAccess.save();
        res.json({ success: true, access: newAccess });
    } catch (err) {
        console.error('[API] POST HWID Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

router.patch('/hwid/:id', verifyUser, async (req, res) => {
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ success: false, message: "Invalid ID" });
        }

        const { hwid, name, expiryDays } = req.body;
        let update = { hwid, name };

        if (expiryDays !== undefined) {
            if (expiryDays === "" || expiryDays === null) {
                update.expiryDate = null;
            } else {
                let expiryDate = new Date();
                expiryDate.setDate(expiryDate.getDate() + parseInt(expiryDays));
                update.expiryDate = expiryDate;
            }
        }

        const access = await HWIDAccess.findByIdAndUpdate(id, { $set: update }, { new: true });
        res.json({ success: true, access });
    } catch (err) {
        console.error('[API] PATCH HWID Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

router.delete('/hwid/:id', verifyUser, async (req, res) => {
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ success: false, message: "Invalid ID" });
        }
        await HWIDAccess.findByIdAndDelete(id);
        res.json({ success: true, message: "HWID access removed" });
    } catch (err) {
        console.error('[API] DELETE HWID Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// --- Statistics ---

router.get('/stats/:panelId', verifyUser, async (req, res) => {
    try {
        const { panelId } = req.params;
        if (!mongoose.Types.ObjectId.isValid(panelId)) {
            return res.status(400).json({ success: false, message: "Invalid panel ID" });
        }
        const total = await License.countDocuments({ panelId });
        const active = await License.countDocuments({ panelId, status: 'active' });
        const pause = await License.countDocuments({ panelId, status: 'pause' });
        const ban = await License.countDocuments({ panelId, status: 'ban' });

        res.json({ success: true, stats: { total, active, pause, ban } });
    } catch (err) {
        console.error('[API] GET Stats Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// --- Client Validation (LoginManager.cs) ---

router.post('/validate', async (req, res) => {
    const { type, panel_name, panel_secret, version, hwid, username, password, key } = req.body;

    // 1. Basic Panel Auth (Headers prioritized, then body)
    const pName = req.headers['panel_name'] || panel_name;
    const pSecret = req.headers['panel_secret'] || panel_secret;
    const pVersion = req.headers['version'] || version;

    if (!pName || !pSecret) return res.status(401).json({ success: false, message: "Panel credentials missing" });

    try {
        const panel = await Panel.findOne({ name: pName, secret: pSecret });
        if (!panel) return res.status(401).json({ success: false, message: "Invalid panel credentials" });

        // 2. Version Check
        if (pVersion && panel.version && pVersion !== panel.version) {
            return res.status(403).json({ success: false, message: `Version mismatch! Required: ${panel.version}, Current: ${pVersion}` });
        }

        // 3. Status Check
        if (panel.status === 'disabled') return res.status(403).json({ success: false, message: "Panel is disabled" });

        // 4. Handle Login Types
        if (type === 'public') {
            if (username === panel.publicLogin.username && password === panel.publicLogin.password) {
                return res.json({ success: true, message: "Public login successful", user: { username: "Public User" } });
            }
            return res.status(401).json({ success: false, message: "Invalid public credentials" });
        }

        if (type === 'hwid') {
            const access = await HWIDAccess.findOne({ panelId: panel._id, hwid });
            if (!access) return res.status(401).json({ success: false, message: "HWID not whitelisted" });
            if (access.expiryDate && new Date() > access.expiryDate) return res.status(403).json({ success: false, message: "HWID access expired" });
            return res.json({ success: true, message: `HWID login successful as ${access.name}` });
        }

        if (type === 'login') {
            const user = await License.findOne({ panelId: panel._id, username, password });
            if (!user) return res.status(401).json({ success: false, message: "Invalid username or password" });
            if (user.status === 'ban') return res.status(403).json({ success: false, message: `User banned: ${user.reason || "No reason"}` });
            if (user.status === 'pause') return res.status(403).json({ success: false, message: "User account paused" });
            if (user.expiryDate && new Date() > user.expiryDate) return res.status(403).json({ success: false, message: "Account expired" });

            // Auto-set HWID if null
            if (!user.hwid) {
                user.hwid = hwid;
                await user.save();
            } else if (user.hwid !== hwid) {
                return res.status(403).json({ success: false, message: "HWID mismatch! Reset HWID on dashboard." });
            }

            const expiryDays = Math.ceil((user.expiryDate - new Date()) / (1000 * 60 * 60 * 24));
            return res.json({ success: true, message: "Login successful", expiryDays });
        }

        if (type === 'key') {
            const user = await License.findOne({ panelId: panel._id, key });
            if (!user) return res.status(401).json({ success: false, message: "Invalid license key" });
            // ... similar checks as login
            if (user.status === 'ban') return res.status(403).json({ success: false, message: "Key banned" });
            if (user.expiryDate && new Date() > user.expiryDate) return res.status(403).json({ success: false, message: "Key expired" });

            if (!user.hwid) {
                user.hwid = hwid;
                await user.save();
            } else if (user.hwid !== hwid) {
                return res.status(403).json({ success: false, message: "HWID mismatch" });
            }

            const expiryDays = Math.ceil((user.expiryDate - new Date()) / (1000 * 60 * 60 * 24));
            return res.json({ success: true, message: "Key validated", expiryDays });
        }

        return res.status(400).json({ success: false, message: "Invalid login type" });

    } catch (err) {
        console.error('[API] Validate Error:', err);
        res.status(500).json({ success: false, message: "Server error during validation" });
    }
});

module.exports = router;
