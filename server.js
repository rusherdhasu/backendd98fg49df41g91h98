const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../Frontend')));

const apiRoutes = require('./routes/api');
const authRoutes = require('./routes/auth');
const { initBot } = require('./bot/bot');

app.use('/api', apiRoutes);
app.use('/api/auth', authRoutes);

// Database Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('✅ Connected to MongoDB');
        initBot();

        // Start Server inside DB connection for reliability
        app.listen(PORT, () => {
            console.log(`🚀 Server running on port ${PORT}`);
        });
    })
    .catch(err => {
        console.error('❌ MongoDB Connection Error:', err);
        process.exit(1);
    });

// Global Error Handler
app.use((err, req, res, next) => {
    console.error('SERVER ERROR STACK:', err.stack);
    res.status(500).json({ success: false, message: "Internal Server Error", error: err.message });
});
