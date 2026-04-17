const axios = require('axios');

const PHIMAPI_BASE = 'https://phimapi.com';
const TIMEOUT = 15000;

async function proxyTmdbMovie(id) {
    const response = await axios.get(`${PHIMAPI_BASE}/tmdb/movie/${encodeURIComponent(id)}`, { timeout: TIMEOUT });
    return response.data;
}

async function proxyTmdbTV(id) {
    const response = await axios.get(`${PHIMAPI_BASE}/tmdb/tv/${encodeURIComponent(id)}`, { timeout: TIMEOUT });
    return response.data;
}

async function searchPhimapi(keyword, year) {
    let url = `${PHIMAPI_BASE}/v1/api/tim-kiem?keyword=${encodeURIComponent(keyword)}`;
    if (year) url += `&year=${encodeURIComponent(year)}`;

    const response = await axios.get(url, { timeout: TIMEOUT });
    const itemCount = response.data?.data?.items?.length || 0;
    return response.data;
}

async function getDetail(slug) {
    const response = await axios.get(`${PHIMAPI_BASE}/phim/${encodeURIComponent(slug)}`, { timeout: TIMEOUT });
    const episodesCount = response.data?.episodes?.length || 0;
    return response.data;
}

module.exports = {
    proxyTmdbMovie,
    proxyTmdbTV,
    searchPhimapi,
    getDetail
};
