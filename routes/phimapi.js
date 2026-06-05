const express = require('express');
const router = express.Router();
const phimapiController = require('../controllers/phimapiController');

// Proxy: TMDB movie lookup
// GET /tmdb/movie/:id → https://phimapi.com/tmdb/movie/:id
router.get('/tmdb/movie/:id', phimapiController.tmdbMovieLookup);

// Proxy: TMDB TV lookup
// GET /tmdb/tv/:id → https://phimapi.com/tmdb/tv/:id
router.get('/tmdb/tv/:id', phimapiController.tmdbTVLookup);

// Proxy: Search
// GET /search?keyword=...&year=... → https://phimapi.com/v1/api/tim-kiem?keyword=...&year=...
router.get('/search', phimapiController.search);

// Proxy: Movie/TV detail by slug
// GET /detail/:slug → https://phimapi.com/phim/:slug
router.get('/detail/:slug', phimapiController.getDetail);

module.exports = router;
