const mongoose = require('mongoose');

const hwidAccessSchema = new mongoose.Schema({
    panelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Panel', required: true },
    hwid: { type: String, required: true },
    name: { type: String, required: true },
    expiryDate: { type: Date, default: null }, // null for infinite
    createdAt: { type: Date, default: Date.now }
});

// Compound index to ensure HWID is unique per panel
hwidAccessSchema.index({ panelId: 1, hwid: 1 }, { unique: true });

module.exports = mongoose.model('HWIDAccess', hwidAccessSchema);
