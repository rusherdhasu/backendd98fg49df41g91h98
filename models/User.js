const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: { type: String, sparse: true, unique: true }, // Gmail/Email for login
    username: { type: String, required: true }, // Display name or Discord username
    password: { type: String }, // Hashed password
    discordId: { type: String, unique: true, sparse: true },
    avatar: { type: String },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
