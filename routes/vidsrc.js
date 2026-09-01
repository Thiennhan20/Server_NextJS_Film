const express = require('express');
const router = express.Router();
const vidsrcController = require('../controllers/vidsrcController');

router.options('*', (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', '*');
    res.status(200).end();
});

router.get('/active-domain', vidsrcController.getActiveDomain);
router.get('/embed-proxy', vidsrcController.embedProxy);
router.all('/proxy', vidsrcController.proxyStream);

module.exports = router;
