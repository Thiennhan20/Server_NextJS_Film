const tmdbService = require('../services/tmdbService');

const applyCacheHeaders = (res, result) => {
    if (result.fromCache) {
        res.set({ 'Content-Type': 'application/json', 'X-Cache': 'HIT' });
        return;
    }

    res.set({
        'Cache-Control': 'public, max-age=1800, stale-while-revalidate=86400',
        'Content-Type': 'application/json',
        'X-Cache': 'MISS'
    });
};

// TMDB proxy route
const proxyTmdbRequest = async (req, res) => {
    try {
        const { endpoint, ...params } = req.query;

        const result = await tmdbService.fetchFromTmdb(endpoint, params);

        applyCacheHeaders(res, result);
        res.json(result.data);
    } catch (error) {
        if (error.status) {
            return res.status(error.status).json({
                error: error.error,
                details: error.details
            });
        }
        console.error('💥 TMDB API error:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
};

const getHomeBundle = async (req, res) => {
    try {
        const result = await tmdbService.fetchHomeBundle();
        applyCacheHeaders(res, result);
        res.json(result.data);
    } catch (error) {
        if (error.status) {
            return res.status(error.status).json({
                error: error.error,
                details: error.details
            });
        }
        console.error('💥 TMDB home bundle error:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
};

module.exports = {
    proxyTmdbRequest,
    getHomeBundle
};
