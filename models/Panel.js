const mongoose = require('mongoose');

const panelSchema = new mongoose.Schema({
    ownerId: { type: String, required: true }, // Discord User ID
    name: { type: String, required: true, unique: true },
    secret: { type: String, required: true }, // API secret for client communication
    version: { type: String, default: "1.0.0" },
    status: { type: String, enum: ['active', 'disabled'], default: 'active' },
    publicLogin: {
        username: { type: String, default: "" },
        password: { type: String, default: "" }
    },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Panel', panelSchema);
