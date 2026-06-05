const phimapiService = require('../services/phimapiService');
const hlsCleanService = require('../services/hlsCleanService');

// Proxy: TMDB movie lookup
const tmdbMovieLookup = async (req, res) => {
    try {
        const { id } = req.params;
        const data = await phimapiService.proxyTmdbMovie(id);
        res.json(data);
    } catch (e) {
        if (e.response) {
            res.status(e.response.status).json(e.response.data);
        } else {
            res.status(500).json({ error: 'Proxy error' });
        }
    }
};

// Proxy: TMDB TV lookup
const tmdbTVLookup = async (req, res) => {
    try {
        const { id } = req.params;
        const data = await phimapiService.proxyTmdbTV(id);
        res.json(data);
    } catch (e) {
        if (e.response) {
            res.status(e.response.status).json(e.response.data);
        } else {
            res.status(500).json({ error: 'Proxy error' });
        }
    }
};

// Proxy: Search
const search = async (req, res) => {
    try {
        const { keyword, year } = req.query;
        if (!keyword) {
            return res.status(400).json({ error: 'Missing keyword parameter' });
        }

        const data = await phimapiService.searchPhimapi(keyword, year);
        const requestBaseUrl = hlsCleanService.getRequestBaseUrl(req);
        res.json(hlsCleanService.wrapPhimapiLinks(data, requestBaseUrl));
    } catch (e) {
        if (e.response) {
            res.status(e.response.status).json(e.response.data);
        } else {
            res.status(500).json({ error: 'Proxy error' });
        }
    }
};

// Proxy: Movie/TV detail by slug
const getDetail = async (req, res) => {
    try {
        const { slug } = req.params;
        const data = await phimapiService.getDetail(slug);
        const requestBaseUrl = hlsCleanService.getRequestBaseUrl(req);
        res.json(hlsCleanService.wrapPhimapiLinks(data, requestBaseUrl));
    } catch (e) {
        if (e.response) {
            res.status(e.response.status).json(e.response.data);
        } else {
            res.status(500).json({ error: 'Proxy error' });
        }
    }
};

// HLS clean playlist for server 1. This rewrites the playlist only; media segments stay on the original host.
const hlsCleanPlaylist = async (req, res) => {
    try {
        const sourceUrl = req.query.source || req.query.url;
        const requestBaseUrl = hlsCleanService.getRequestBaseUrl(req);
        const body = await hlsCleanService.getCleanPlaylist(sourceUrl, requestBaseUrl);

        res.set({
            'Content-Type': 'application/vnd.apple.mpegurl; charset=utf-8',
            'Cache-Control': 'no-store',
        });
        res.send(body);
    } catch (e) {
        res.status(400).json({ error: e.message || 'Failed to clean HLS playlist' });
    }
};

module.exports = {
    tmdbMovieLookup,
    tmdbTVLookup,
    search,
    getDetail,
    hlsCleanPlaylist
};
