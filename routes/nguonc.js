const express = require('express');
const router = express.Router();
const nguoncController = require('../controllers/nguoncController');

// Search TV Show
router.get('/search-tv', nguoncController.searchTVShow);

// Search Movie
router.get('/search-movie', nguoncController.searchMovie);

// Embed Proxy (Clean Ads, Bypass Cloudflare & iOS fix)
router.get('/embed-proxy', nguoncController.embedProxy);

// Stream & Segment Proxy
router.get('/proxy', nguoncController.proxyStream);

module.exports = router;
