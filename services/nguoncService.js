const axios = require('axios');

// Helper: Normalize string for comparison (remove diacritics, lowercase, remove punctuation)
function normalizeForCompare(str) {
    if (!str) return '';
    return str.normalize('NFD') // Decompose combined characters
        .replace(/[\u0300-\u036f]/g, '') // Remove diacritics
        .toLowerCase()
        .replace(/[''""]/g, '') // Remove all types of quotes/apostrophes
        .replace(/[^\w\s]/g, '') // Remove all punctuation except spaces
        .replace(/\s+/g, ' ') // Replace multiple spaces with a single space
        .trim();
}

// Helper: Extract season from title/slug
function extractSeasonFromTitle(title, slug) {
    const titleMatch = title.match(/[\s(]?(?:ph[aầ]n|season|m[uù]a)[\s-]*(\d+)[\s)]?/i);
    if (titleMatch) return parseInt(titleMatch[1]);
    const slugMatch = slug.match(/-(?:phan|season|mua)-(\d+)(?:-|$)/i);
    if (slugMatch) return parseInt(slugMatch[1]);
    // Check trailing number in slug: "toan-chuc-phap-su-6" → 6
    const slugTrailing = slug.match(/-(\d+)$/);
    if (slugTrailing) {
        const num = parseInt(slugTrailing[1]);
        if (num < 100) return num;
    }
    // Check trailing number in name: "Toàn Chức Pháp Sư 6" → 6
    const nameTrailing = title.trim().match(/\s(\d+)$/);
    if (nameTrailing) {
        const num = parseInt(nameTrailing[1]);
        if (num < 100) return num;
    }
    return null;
}

// Helper: Check if title contains any season indicator without a number
function titleContainsSeason(title, slug) {
    if (/ph[aầ]n/i.test(title) || /phan/i.test(slug) ||
        /season/i.test(title) || /season/i.test(slug) ||
        /m[uù]a/i.test(title) || /mua/i.test(slug)) return true;
    // Also detect trailing numbers as season indicators
    if (/\s\d+$/.test(title.trim())) return true;
    if (/-(\d+)$/.test(slug)) return true;
    return false;
}

// Helper: Fetch film by slug (with retry)
async function fetchFilmBySlug(slug) {
    try {
        const res = await axios.get(`https://phim.nguonc.com/api/film/${encodeURIComponent(slug)}`);
        if (res.data?.status === 'success' && res.data?.movie) {
            return res.data.movie;
        }
    } catch (e) {
    }
    return null;
}

// Helper: Search nguonc api (all pages up to 5, with retry per request)
async function searchNguonc(keyword, targetOriginalName) {
    const allItems = [];
    let page = 1;
    let totalPages = 1;

    try {
        while (page <= totalPages && page <= 5) {
            const res = await axios.get(`https://phim.nguonc.com/api/films/search?keyword=${encodeURIComponent(keyword.trim())}&page=${page}`);
            const data = res.data;
            if (data?.status !== 'success' || !data.items || data.items.length === 0) {
                break;
            }

            allItems.push(...data.items);
            totalPages = data.paginate?.total_page || 1;

            if (targetOriginalName) {
                const target = normalizeForCompare(targetOriginalName);
                const nameMatch = data.items.find(i => normalizeForCompare(i.original_name || '') === target);
                if (nameMatch) break;
            }

            if (totalPages <= 1) break;
            page++;
        }
    } catch (e) {
    }
    return allItems;
}

// Get the best match for a TV show
async function getBestMatchTVShow(keyword, normalizedTitle, cleanTitle, season, tmdbYear) {
    // 1. Search by keyword
    let items = await searchNguonc(keyword);

    // 1a. Variations for season searches
    const seasonKeywords = [
        `${keyword} ${season}`,
        `${keyword} phần ${season}`,
        `${keyword} season ${season}`,
        `${keyword} mùa ${season}`,
        `${keyword}(season ${season})`,
        `${keyword} (season ${season})`,
        `${keyword} ( season ${season} )`,
        `${keyword}(season${season})`,
        `${keyword}(phần ${season})`,
        `${keyword} (phần ${season})`,
        `${keyword} ( phần ${season} )`,
        `${keyword}(phần${season})`
    ];
    for (const sk of seasonKeywords) {
        const extra = await searchNguonc(sk);
        const existingSlugs = new Set(items.map(i => i.slug));
        for (const item of extra) {
            if (!existingSlugs.has(item.slug)) {
                items.push(item);
                existingSlugs.add(item.slug);
            }
        }
    }

    // Fallback: search with Vietnamese name if English name misses the season
    if (items.length > 0) {
        let hasCorrectSeason = false;
        for (const item of items) {
            const sn = extractSeasonFromTitle(item.name || '', item.slug || '');
            if ((season === 1 && (sn === 1 || sn === null)) || (season > 1 && sn === season)) {
                hasCorrectSeason = true;
                break;
            }
        }
        if (!hasCorrectSeason && normalizedTitle && normalizedTitle !== cleanTitle) {
            const viItems = await searchNguonc(normalizedTitle);
            items = viItems; // Replace items
        }
    }

    // Search with year if no results
    if (items.length === 0 && tmdbYear) {
        const yearKeyword = `${cleanTitle} ${tmdbYear}`;
        items = await searchNguonc(yearKeyword);
    }

    if (items.length === 0) {
        return null;
    }

    // Filter by name match
    const nameMatches = items.filter((item) => {
        const viName = item.name?.toLowerCase().trim() || '';
        if (viName === normalizedTitle) return true;
        const aliases = (item.original_name || '').split(',').map(a => normalizeForCompare(a));
        return aliases.some(alias =>
            alias === cleanTitle ||
            alias.startsWith(cleanTitle + ' ') ||
            alias.startsWith(cleanTitle + ':')
        );
    });

    const candidates = nameMatches.length > 0 ? nameMatches : items;
    let bestMatch = candidates[0];
    let bestScore = -1;

    for (const candidate of candidates) {
        let score = 0;
        const viName = candidate.name?.toLowerCase().trim() || '';
        const viNameBase = viName.replace(/ ph[aầ]n \d+$/i, '').replace(/ season \d+$/i, '').replace(/ m[uù]a \d+$/i, '').trim();

        const aliases = (candidate.original_name || '').split(',').map(a => normalizeForCompare(a));
        const hasExactBaseAlias = aliases.some(a => {
            const baseAlias = a.replace(/ season \d+$/, '').replace(/ ph[aầ]n \d+$/, '').replace(/ m[uù]a \d+$/, '').trim();
            return baseAlias === cleanTitle || a === cleanTitle;
        });

        const hasPartialAlias = aliases.some(a => a.startsWith(cleanTitle + ' ') || a.startsWith(cleanTitle + ':'));

        if (hasExactBaseAlias || viNameBase === normalizedTitle || viName === normalizedTitle) score += 3;
        else if (hasPartialAlias) score += 1;

        const detectedSeason = extractSeasonFromTitle(candidate.name || '', candidate.slug || '');
        if (season === 1) {
            if (detectedSeason === null && !titleContainsSeason(candidate.name || '', candidate.slug || '')) {
                score += 3;
            } else if (detectedSeason === 1) {
                score += 3;
            } else if (detectedSeason !== null && detectedSeason !== 1) {
                score -= 5;
            }
        } else {
            if (detectedSeason === season) {
                score += 5;
            } else if (detectedSeason !== null && detectedSeason !== season) {
                score -= 5;
            } else {
                score -= 2;
            }
        }

        if (score > bestScore) {
            bestScore = score;
            bestMatch = candidate;
        }
    }

    // Verify with detail API — check ALL candidates, not just 4
    if (tmdbYear || season > 1) {
        const toVerify = [bestMatch, ...candidates.filter(m => m.slug !== bestMatch.slug)];
        for (const candidate of toVerify) {
            const detail = await fetchFilmBySlug(candidate.slug);
            if (detail?.category) {
                const yearStr = Object.values(detail.category).find(cat => cat.group?.name === 'Năm')?.list?.[0]?.name;
                const detailYear = yearStr ? parseInt(yearStr) : 0;
                // For season > 1, relax year matching since TMDB year is first-air-date
                // which differs from individual season release years
                const yearMatch = detailYear === tmdbYear;
                const yearClose = Math.abs(detailYear - tmdbYear) <= 10; // Same franchise within 10 years
                const detailSeason = extractSeasonFromTitle(detail.name || '', detail.slug || '');
                const seasonMatch = season === 1
                    ? (detailSeason === null || detailSeason === 1)
                    : detailSeason === season;

                // For season > 1: prioritize season match, relax year requirement
                if (seasonMatch && detail.episodes) {
                    if (yearMatch || yearClose || season > 1) {
                        return detail;
                    }
                }
            }
        }
    }

    // Fallback: If no single clear match via Year, just pick the best scoring item and fetch details
    // BUT only if bestScore is positive (not a wrong-season match)
    if (bestScore < 0) {
        return null;
    }
    const fallbackDetail = await fetchFilmBySlug(bestMatch.slug);
    
    // Final season verification on the fetched detail
    if (fallbackDetail) {
        const fallbackSeason = extractSeasonFromTitle(fallbackDetail.name || '', fallbackDetail.slug || '');
        const seasonOk = season === 1
            ? (fallbackSeason === null || fallbackSeason === 1)
            : fallbackSeason === season;
        if (!seasonOk) {
            return null;
        }
    }
    return fallbackDetail;
}

// Extract TV show links
function extractLinksForEpisode(episodesData, selectedEpisode) {
    let bestVietsub = '';
    let bestDubbed = '';
    let fallback = '';

    for (const epServer of episodesData) {
        const serverName = normalizeForCompare(epServer.server_name || '');
        const isVietsub = serverName.includes('vietsub');
        const isDubbed = serverName.includes('thuyet minh') || serverName.includes('long tieng') || serverName.includes('dubbed');

        const serverData = epServer.server_data || epServer.items;
        const epData = serverData?.find(ep => {
            const n = ep.name?.toLowerCase() || '';
            // Nguonc api often uses "phần", "tập full", "full" as name too, need exact or fallback matches
            return n === `tập ${selectedEpisode}` ||
                n === `episode ${selectedEpisode}` ||
                n === selectedEpisode.toString() ||
                n === `tập ${selectedEpisode.toString().padStart(2, '0')}` ||
                n === 'full' || n === 'tập full';
        });

        if (epData) {
            const link = epData.embed || epData.link_embed || epData.m3u8 || epData.link_m3u8;
            if (isVietsub && link) bestVietsub = link;
            if (isDubbed && link) bestDubbed = link;
            if (link) fallback = link;
        }
    }
    return {
        vietsub: bestVietsub,
        dubbed: bestDubbed,
        m3u8: fallback || bestVietsub || bestDubbed
    };
}

// Search Movie helpers
function directorsMatch(tmdbDirector, nguoncDirector) {
    if (!tmdbDirector || !nguoncDirector) return false;
    const cleanTmdb = normalizeForCompare(tmdbDirector);
    if (!cleanTmdb) return false;
    const ngDirs = nguoncDirector.split(',').map(d => normalizeForCompare(d));
    return ngDirs.some(d => d === cleanTmdb || d.includes(cleanTmdb) || cleanTmdb.includes(d));
}

async function getBestMatchMovie(keyword, normalizedTitle, cleanTitle, tmdbYear, tmdbDirector) {
    let items = await searchNguonc(keyword);

    if (items.length === 0 && tmdbYear) {
        const yearKeyword = `${cleanTitle} ${tmdbYear}`;
        items = await searchNguonc(yearKeyword);
    }
    if (items.length === 0) return null;

    let nameMatches = items.filter((item) => {
        const origName = normalizeForCompare(item.original_name || '');
        const viName = item.name?.toLowerCase().trim() || '';
        return origName === cleanTitle || viName === normalizedTitle;
    });

    const candidates = nameMatches.length > 0 ? nameMatches : items;
    let bestMatch = candidates[0];
    let bestScore = -1;

    for (const candidate of candidates) {
        let score = 0;
        const origName = normalizeForCompare(candidate.original_name || '');
        const viName = candidate.name?.toLowerCase().trim() || '';

        if (viName === normalizedTitle) score += 3;
        else if (viName.startsWith(normalizedTitle + ' ')) score += 1;

        if (origName === cleanTitle) score += 3;
        else if (origName.startsWith(cleanTitle + ' ')) score += 1;

        if (tmdbDirector && candidate.director) {
            if (directorsMatch(tmdbDirector, candidate.director)) {
                score += 2;
            } else {
                score -= 1;
            }
        }

        if (score > bestScore) {
            bestScore = score;
            bestMatch = candidate;
        }
    }

    if (bestScore > 0 && bestScore < 5 && tmdbYear) {
        const toVerify = [bestMatch, ...nameMatches.filter(m => m.slug !== bestMatch.slug)];
        for (const candidate of toVerify) {
            const detail = await fetchFilmBySlug(candidate.slug);
            if (detail?.category) {
                const yearStr = Object.values(detail.category).find(cat => cat.group?.name === 'Năm')?.list?.[0]?.name;
                if (yearStr && parseInt(yearStr) === tmdbYear) {
                    return detail;
                }
            }
        }
    }

    // Fallback if detail-year check failed
    return fetchFilmBySlug(bestMatch.slug);
}

function extractMovieLinks(detail) {
    let m3u8 = '';
    let dubbed = '';
    let vietsub = '';

    if (detail.episodes) {
        for (const episode of detail.episodes) {
            const serverData = episode.server_data || episode.items;
            if (serverData && serverData.length > 0) {
                const serverName = normalizeForCompare(episode.server_name || '');
                const epData = serverData[0];
                const link = epData.embed || epData.link_embed || epData.m3u8 || epData.link_m3u8;
                if (serverName.includes('thuyet minh') || serverName.includes('long tieng') || serverName.includes('dubbed')) {
                    dubbed = link;
                } else if (serverName.includes('vietsub')) {
                    vietsub = link;
                } else if (!m3u8) {
                    m3u8 = link;
                }
            }
        }
    }
    return {
        vietsub: vietsub || m3u8,
        dubbed: dubbed,
        m3u8: m3u8 || vietsub || dubbed
    };
}

module.exports = {
    normalizeForCompare,
    extractSeasonFromTitle,
    titleContainsSeason,
    fetchFilmBySlug,
    searchNguonc,
    getBestMatchTVShow,
    extractLinksForEpisode,
    directorsMatch,
    getBestMatchMovie,
    extractMovieLinks
};
