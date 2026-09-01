const express = require('express');
const router = express.Router();
const vidsrcController = require('../controllers/vidsrcController');

router.get('/active-domain', vidsrcController.getActiveDomain);
router.get('/embed-proxy', vidsrcController.embedProxy);
router.get('/proxy', vidsrcController.proxyStream);

module.exports = router;
