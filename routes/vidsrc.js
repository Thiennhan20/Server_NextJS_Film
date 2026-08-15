const express = require('express');
const router = express.Router();
const vidsrcController = require('../controllers/vidsrcController');

router.get('/active-domain', vidsrcController.getActiveDomain);

module.exports = router;
