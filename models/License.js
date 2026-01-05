const mongoose = require('mongoose');

const licenseSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: false },
    key: { type: String, unique: true, sparse: true },
    panelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Panel', required: true },
    expiryDate: { type: Date, required: true },
    reason: { type: String, default: "" },
    hwid: { type: String, default: null },
    usedAt: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now },
    status: { type: String, enum: ['active', 'pause', 'ban'], default: 'active' }
});

module.exports = mongoose.model('License', licenseSchema);
