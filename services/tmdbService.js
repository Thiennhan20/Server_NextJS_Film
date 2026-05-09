const NodeCache = require('node-cache');
require('dotenv').config();

const TMDB_API_KEY = process.env.TMDB_API_KEY;
const TMDB_BASE_URL = 'https://api.themoviedb.org/3';

// In-memory cache (no Redis needed)
const cache = new NodeCache({ checkperiod: 120 }); // Check for expired keys every 2 min

// SSRF Protection: Whitelist of allowed TMDB endpoint patterns
const ALLOWED_ENDPOINTS = [
    /^\/movie\/\d+$/,                          // /movie/{id}
    /^\/movie\/\d+\/(credits|videos|images|similar|recommendations)$/,
    /^\/movie\/(popular|upcoming|now_playing|top_rated)$/,
    /^\/tv\/\d+$/,                             // /tv/{id}
    /^\/tv\/\d+\/(credits|videos|images|similar|recommendations)$/,
    /^\/tv\/\d+\/season\/\d+$/,               // /tv/{id}/season/{num}
    /^\/tv\/(popular|airing_today|on_the_air|top_rated)$/,
    /^\/trending\/(movie|tv)\/(day|week)$/,    // /trending/{type}/{window}
    /^\/search\/(multi|movie|tv)$/,            // /search/{type}
    /^\/discover\/(movie|tv)$/,                // /discover/{type}
];

function isEndpointAllowed(endpoint) {
    const pathOnly = endpoint.split('?')[0];
    return ALLOWED_ENDPOINTS.some(pattern => pattern.test(pathOnly));
}

// Get TTL (seconds) based on endpoint type
function getTTL(endpoint) {
    if (/^\/movie\/\d+$/.test(endpoint) || /^\/tv\/\d+$/.test(endpoint)) return 7200;       // 2h - movie/tv details
    if (/\/(credits|videos|images)$/.test(endpoint)) return 7200;                             // 2h - credits/videos/images
    if (/\/(similar|recommendations)$/.test(endpoint)) return 3600;                           // 1h - similar/recommendations
    if (/\/season\/\d+$/.test(endpoint)) return 3600;                                         // 1h - tv seasons
    if (/\/(popular|trending|now_playing|upcoming|top_rated|airing_today|on_the_air)/.test(endpoint)) return 1800; // 30min
    if (/\/discover\//.test(endpoint)) return 1800;                                           // 30min - discover
    if (/\/search\//.test(endpoint)) return 900;                                              // 15min - search
    return 1800; // Default 30min
}

async function fetchFromTmdb(endpoint, params) {
    if (!TMDB_API_KEY) {
        throw { status: 500, error: 'TMDB API key not configured' };
    }

    if (!endpoint) {
        throw { status: 400, error: 'Endpoint parameter is required' };
    }

    // SSRF Protection: Validate endpoint against whitelist
    if (!isEndpointAllowed(endpoint)) {
        console.warn('⚠️ Blocked disallowed endpoint:', endpoint);
        throw { status: 403, error: 'Endpoint not allowed' };
    }

    // Build cache key from endpoint + params
    const cacheKey = `tmdb:${endpoint}:${JSON.stringify(params)}`;

    // Check cache first
    const cached = cache.get(cacheKey);
    if (cached) {
        return { data: cached, fromCache: true };
    }

    // Cache miss → fetch from TMDB
    const tmdbUrl = new URL(`${TMDB_BASE_URL}${endpoint}`);
    tmdbUrl.searchParams.set('api_key', TMDB_API_KEY);

    Object.entries(params).forEach(([key, value]) => {
        if (value) tmdbUrl.searchParams.set(key, String(value));
    });

    const response = await fetch(tmdbUrl.toString());

    if (!response.ok) {
        const errorText = await response.text();
        throw { status: response.status, error: 'TMDB API request failed', details: errorText };
    }

    const data = await response.json();

    // Save to cache with endpoint-specific TTL
    cache.set(cacheKey, data, getTTL(endpoint));

    return { data, fromCache: false };
}

module.exports = {
    isEndpointAllowed,
    getTTL,
    fetchFromTmdb
};
