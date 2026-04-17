const nguoncService = require('../services/nguoncService');

// Search TV Show
const searchTVShow = async (req, res) => {
    try {
        const { keyword, name, year, season, episode } = req.query;
        if (!keyword) {
            return res.status(400).json({ error: 'Missing keyword parameter' });
        }

        const normalizedTitle = name ? name.toLowerCase().trim() : '';
        const cleanTitle = nguoncService.normalizeForCompare(keyword);
        const tmdbYear = parseInt(year) || 0;
        const selectedSeason = parseInt(season) || 1;
        const selectedEpisode = parseInt(episode) || 1;
        const detail = await nguoncService.getBestMatchTVShow(keyword, normalizedTitle, cleanTitle, selectedSeason, tmdbYear);

        if (detail && detail.episodes) {
            const links = nguoncService.extractLinksForEpisode(detail.episodes, selectedEpisode);
            return res.json({ status: 'success', data: { detail, links } });
        }
        res.json({ status: 'not_found' });
    } catch (e) {
        res.status(500).json({ error: 'Server Error' });
    }
};

// Search Movie
const searchMovie = async (req, res) => {
    try {
        const { keyword, name, year, director } = req.query;
        if (!keyword) {
            return res.status(400).json({ error: 'Missing keyword parameter' });
        }
        const normalizedTitle = name ? name.toLowerCase().trim() : '';
        const cleanTitle = nguoncService.normalizeForCompare(keyword);
        const tmdbYear = parseInt(year) || 0;

        const detail = await nguoncService.getBestMatchMovie(keyword, normalizedTitle, cleanTitle, tmdbYear, director);
        if (detail) {
            const links = nguoncService.extractMovieLinks(detail);
            return res.json({ status: 'success', data: { detail, links } });
        }

        res.json({ status: 'not_found' });
    } catch (e) {
        res.status(500).json({ error: 'Server Error' });
    }
};

module.exports = {
    searchTVShow,
    searchMovie
};
