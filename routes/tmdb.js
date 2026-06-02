const express = require('express');
const router = express.Router();
const tmdbController = require('../controllers/tmdbController');

router.get('/home', tmdbController.getHomeBundle);

// TMDB proxy route
router.get('/', tmdbController.proxyTmdbRequest);

module.exports = router;
