const NodeCache = require('node-cache');
const redis = require('../config/redis');
require('dotenv').config();

const TMDB_API_KEY = process.env.TMDB_API_KEY;
const TMDB_BASE_URL = 'https://api.themoviedb.org/3';

// Redis-first cache with in-memory fallback.
const cache = new NodeCache({ checkperiod: 120 }); // Check for expired keys every 2 min
const HOME_BUNDLE_TTL = 1800;

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
    /^\/trending\/person\/(day|week)$/,        // /trending/person/{window}
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

function parseCachedValue(value) {
    if (!value) return null;
    if (typeof value !== 'string') return value;
    try {
        return JSON.parse(value);
    } catch {
        return value;
    }
}

async function getCachedValue(cacheKey) {
    const redisValue = parseCachedValue(await redis.get(cacheKey));
    if (redisValue) return redisValue;
    return cache.get(cacheKey) || null;
}

async function setCachedValue(cacheKey, data, ttlSeconds) {
    cache.set(cacheKey, data, ttlSeconds);
    await redis.set(cacheKey, data, ttlSeconds);
}

async function fetchFromTmdb(endpoint, params = {}) {
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
    const cached = await getCachedValue(cacheKey);
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
    await setCachedValue(cacheKey, data, getTTL(endpoint));

    return { data, fromCache: false };
}

function getDateRange(daysAhead = 90) {
    const today = new Date();
    const startDate = today.toISOString().split('T')[0];
    const endDate = new Date(today);
    endDate.setDate(today.getDate() + daysAhead);

    return {
        startDate,
        endDate: endDate.toISOString().split('T')[0],
    };
}

function getResults(result) {
    return result?.data?.results || [];
}

async function fetchHomeResource(endpoint, params = {}) {
    try {
        return await fetchFromTmdb(endpoint, params);
    } catch (error) {
        if (error?.error === 'TMDB API key not configured') {
            throw error;
        }

        console.warn('TMDB home resource failed:', endpoint, error?.status || error?.message || error?.error);
        return { data: { results: [] }, fromCache: false, failed: true };
    }
}

function withMediaType(items, mediaType, limit) {
    return (items || [])
        .filter(item => item?.poster_path || item?.backdrop_path || item?.profile_path)
        .slice(0, limit)
        .map(item => ({ ...item, media_type: mediaType }));
}

function interleave(primary, secondary, limit = 15) {
    const combined = [];
    const max = Math.max(primary.length, secondary.length);

    for (let index = 0; index < max && combined.length < limit; index += 1) {
        if (primary[index]) combined.push(primary[index]);
        if (secondary[index] && combined.length < limit) combined.push(secondary[index]);
    }

    return combined;
}

async function fetchHomeBundle() {
    const { startDate, endDate } = getDateRange(90);
    const cacheKey = `tmdb:home:v2:${startDate}`;

    const cached = await getCachedValue(cacheKey);
    if (cached) {
        return { data: cached, fromCache: true };
    }

    const [
        trendingMovies,
        trendingTV,
        topRatedMovies,
        topMovies,
        topTVShows,
        koreanMovies,
        koreanTV,
        usukMovies,
        usukTV,
        chinaMovies,
        chinaTV,
        comingSoon,
        animeMovies,
        animeTV,
        actionMovies,
        actionTV,
        horrorMovies,
        horrorTV,
        romanceMovies,
        romanceTV,
        actors,
    ] = await Promise.all([
        fetchHomeResource('/trending/movie/week', {}),
        fetchHomeResource('/trending/tv/week', {}),
        fetchHomeResource('/movie/top_rated', {}),
        fetchHomeResource('/trending/movie/day', {}),
        fetchHomeResource('/trending/tv/day', {}),
        fetchHomeResource('/discover/movie', { with_original_language: 'ko', sort_by: 'popularity.desc' }),
        fetchHomeResource('/discover/tv', { with_original_language: 'ko', sort_by: 'popularity.desc' }),
        fetchHomeResource('/discover/movie', { with_original_language: 'en', region: 'US', sort_by: 'popularity.desc' }),
        fetchHomeResource('/discover/tv', { with_original_language: 'en', with_origin_country: 'US|GB', sort_by: 'popularity.desc' }),
        fetchHomeResource('/discover/movie', { with_original_language: 'zh', sort_by: 'popularity.desc' }),
        fetchHomeResource('/discover/tv', { with_original_language: 'zh', sort_by: 'popularity.desc' }),
        fetchHomeResource('/discover/movie', {
            'release_date.gte': startDate,
            'release_date.lte': endDate,
            with_release_type: '3|6',
            region: 'VN',
            sort_by: 'release_date.asc',
        }),
        fetchHomeResource('/discover/movie', { with_genres: 16, with_original_language: 'ja', sort_by: 'popularity.desc' }),
        fetchHomeResource('/discover/tv', { with_genres: 16, with_original_language: 'ja', sort_by: 'popularity.desc' }),
        fetchHomeResource('/discover/movie', { with_genres: 28, sort_by: 'popularity.desc' }),
        fetchHomeResource('/discover/tv', { with_genres: 10759, sort_by: 'popularity.desc' }),
        fetchHomeResource('/discover/movie', { with_genres: 27, sort_by: 'popularity.desc' }),
        fetchHomeResource('/discover/tv', { with_genres: 9648, sort_by: 'popularity.desc' }),
        fetchHomeResource('/discover/movie', { with_genres: 10749, sort_by: 'popularity.desc' }),
        fetchHomeResource('/discover/tv', { with_genres: 10749, sort_by: 'popularity.desc' }),
        fetchHomeResource('/trending/person/week', {}),
    ]);

    const upcoming = getResults(comingSoon).filter(movie => {
        if (!movie.release_date) return false;
        return new Date(movie.release_date) >= new Date(startDate);
    });

    const data = {
        generatedAt: new Date().toISOString(),
        sections: {
            trendingMovies: withMediaType(getResults(trendingMovies), 'movie', 10),
            trendingTV: withMediaType(getResults(trendingTV), 'tv', 10),
            topRatedMovies: withMediaType(getResults(topRatedMovies), 'movie', 10),
            topMovies: withMediaType(getResults(topMovies), 'movie', 5),
            topTVShows: withMediaType(getResults(topTVShows), 'tv', 5),
            korean: interleave(
                withMediaType(getResults(koreanMovies), 'movie', 8),
                withMediaType(getResults(koreanTV), 'tv', 7),
            ),
            usuk: interleave(
                withMediaType(getResults(usukMovies), 'movie', 8),
                withMediaType(getResults(usukTV), 'tv', 7),
            ),
            china: interleave(
                withMediaType(getResults(chinaMovies), 'movie', 8),
                withMediaType(getResults(chinaTV), 'tv', 7),
            ),
            comingSoon: withMediaType(upcoming, 'movie', 20),
            anime: interleave(
                withMediaType(getResults(animeMovies), 'movie', 8),
                withMediaType(getResults(animeTV), 'tv', 7),
            ),
            action: interleave(
                withMediaType(getResults(actionMovies), 'movie', 8),
                withMediaType(getResults(actionTV), 'tv', 7),
            ),
            horror: interleave(
                withMediaType(getResults(horrorMovies), 'movie', 8),
                withMediaType(getResults(horrorTV), 'tv', 7),
            ),
            romance: interleave(
                withMediaType(getResults(romanceMovies), 'movie', 8),
                withMediaType(getResults(romanceTV), 'tv', 7),
            ),
            actors: withMediaType(getResults(actors), 'person', 12),
        },
    };

    await setCachedValue(cacheKey, data, HOME_BUNDLE_TTL);

    return { data, fromCache: false };
}

module.exports = {
    isEndpointAllowed,
    getTTL,
    fetchFromTmdb,
    fetchHomeBundle
};
