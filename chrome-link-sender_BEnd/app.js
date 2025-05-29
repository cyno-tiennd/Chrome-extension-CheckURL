// app.js
require('dotenv').config(); // Load environment variables from .env

const express = require('express');
const cors = require('cors');
const safeBrowseRoutes = require('./routes/api'); // Sẽ chứa logic kiểm tra URL

const app = express();
const PORT = process.env.PORT || 8005; // Cổng mặc định 8005

// Middleware
app.use(express.json()); // For parsing application/json
app.use(cors()); // Allow cross-origin requests from your extension

// API Routes
// Backend sẽ lắng nghe yêu cầu POST tới /api/check-url
app.use('/api', safeBrowseRoutes);

// Basic route for testing server
app.get('/', (req, res) => {
    res.send('Chrome Link Sender Backend is running!');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Access backend API at http://localhost:${PORT}/api/check-url`);
});