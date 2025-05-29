// routes/api.js
const express = require('express');
const safeBrowseController = require('../controllers/safeBrowseController'); // Tên controller đã có logic kiểm tra

const router = express.Router();

// Định nghĩa endpoint POST để kiểm tra URL
router.post('/check-url', safeBrowseController.checkUrlAndIntegrate); // Endpoint rõ ràng hơn

module.exports = router;