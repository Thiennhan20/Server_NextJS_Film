const axios = require('axios');

const FETCH_TIMEOUT = 15000;
const CACHE_TTL_MS = 5 * 60 * 1000;

const playlistCache = new Map();

function isHttpUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function requireHttpUrl(value) {
  if (!value || !isHttpUrl(value)) {
    throw new Error('Missing or invalid HLS URL.');
  }
  return new URL(value).toString();
}

function normalizeBaseUrl(value) {
  return String(value || '').replace(/\/$/, '');
}

function getRequestBaseUrl(req) {
  if (process.env.PUBLIC_API_BASE_URL) {
    return normalizeBaseUrl(process.env.PUBLIC_API_BASE_URL);
  }

  const forwardedProto = req.get('x-forwarded-proto')?.split(',')[0]?.trim();
  const forwardedHost = req.get('x-forwarded-host')?.split(',')[0]?.trim();
  const protocol = forwardedProto || req.protocol || 'http';
  const host = forwardedHost || req.get('host');

  return normalizeBaseUrl(`${protocol}://${host}`);
}

function resolveUrl(baseUrl, value) {
  return new URL(value, baseUrl).toString();
}

function directoryUrl(url) {
  const parsed = new URL(url);
  parsed.pathname = parsed.pathname.replace(/[^/]*$/, '');
  parsed.search = '';
  parsed.hash = '';
  return parsed.toString();
}

function createCleanPlaylistUrl(sourceUrl, requestBaseUrl) {
  const params = new URLSearchParams({ source: sourceUrl });
  return `${normalizeBaseUrl(requestBaseUrl)}/api/server1/hls-clean/playlist.m3u8?${params.toString()}`;
}

function isCleanPlaylistUrl(value) {
  return typeof value === 'string' && value.includes('/api/server1/hls-clean/playlist.m3u8');
}

function looksLikeHlsUrl(value) {
  return typeof value === 'string' && /\.m3u8(?:$|[?#])/i.test(value);
}

function getEmbeddedHlsUrl(value) {
  if (typeof value !== 'string') return null;

  try {
    const parsed = new URL(value);
    const embedded = parsed.searchParams.get('url');
    if (embedded && looksLikeHlsUrl(embedded) && isHttpUrl(embedded)) {
      return new URL(embedded).toString();
    }
  } catch {
    // Fall through to the string-based parser below.
  }

  const marker = '?url=';
  const markerIndex = value.indexOf(marker);
  if (markerIndex === -1) return null;

  const rawEmbedded = value.slice(markerIndex + marker.length).split('&')[0];
  try {
    const decoded = decodeURIComponent(rawEmbedded);
    return looksLikeHlsUrl(decoded) && isHttpUrl(decoded) ? new URL(decoded).toString() : null;
  } catch {
    return looksLikeHlsUrl(rawEmbedded) && isHttpUrl(rawEmbedded) ? new URL(rawEmbedded).toString() : null;
  }
}

function wrapHlsUrl(value, requestBaseUrl) {
  if (typeof value !== 'string' || isCleanPlaylistUrl(value)) return value;

  const embedded = getEmbeddedHlsUrl(value);
  if (embedded) {
    return createCleanPlaylistUrl(embedded, requestBaseUrl);
  }

  if (looksLikeHlsUrl(value) && isHttpUrl(value)) {
    return createCleanPlaylistUrl(new URL(value).toString(), requestBaseUrl);
  }

  return value;
}

function wrapPhimapiLinks(value, requestBaseUrl) {
  if (Array.isArray(value)) {
    return value.map((item) => wrapPhimapiLinks(item, requestBaseUrl));
  }

  if (!value || typeof value !== 'object') {
    return value;
  }

  const output = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === 'string' && (key === 'link_m3u8' || key === 'm3u8' || key === 'link_embed')) {
      output[key] = wrapHlsUrl(item, requestBaseUrl);
    } else {
      output[key] = wrapPhimapiLinks(item, requestBaseUrl);
    }
  }
  return output;
}

async function fetchPlaylistText(sourceUrl) {
  const response = await axios.get(sourceUrl, {
    timeout: FETCH_TIMEOUT,
    responseType: 'text',
    transformResponse: [(data) => data],
    headers: {
      'user-agent': 'Mozilla/5.0',
    },
  });

  if (typeof response.data !== 'string' || !response.data.includes('#EXTM3U')) {
    throw new Error('The URL does not return a valid M3U8 playlist.');
  }

  return response.data;
}

function rewriteUriAttributes(line, playlistUrl, requestBaseUrl, wrapPlaylistsOnly = false) {
  return line.replace(/URI="([^"]+)"/g, (match, uri) => {
    if (!uri || /^(data|skd):/i.test(uri)) return match;

    const resolved = resolveUrl(playlistUrl, uri);
    if (wrapPlaylistsOnly && looksLikeHlsUrl(resolved)) {
      return `URI="${createCleanPlaylistUrl(resolved, requestBaseUrl)}"`;
    }

    return `URI="${resolved}"`;
  });
}

function isMasterPlaylist(lines) {
  return lines.some((line) => line.startsWith('#EXT-X-STREAM-INF'));
}

function rewriteMasterPlaylist(lines, playlistUrl, requestBaseUrl) {
  const output = [];

  for (const line of lines) {
    if (!line) continue;

    if (line.startsWith('#')) {
      output.push(rewriteUriAttributes(line, playlistUrl, requestBaseUrl, true));
      continue;
    }

    const variantUrl = resolveUrl(playlistUrl, line);
    output.push(createCleanPlaylistUrl(variantUrl, requestBaseUrl));
  }

  return `${output.join('\n')}\n`;
}

function isSegmentScopedTag(line) {
  return (
    line.startsWith('#EXTINF') ||
    line.startsWith('#EXT-X-BYTERANGE') ||
    line.startsWith('#EXT-X-DISCONTINUITY') ||
    line.startsWith('#EXT-X-PROGRAM-DATE-TIME') ||
    line.startsWith('#EXT-X-KEY') ||
    line.startsWith('#EXT-X-MAP') ||
    line.startsWith('#EXT-X-DATERANGE') ||
    line.startsWith('#EXT-X-GAP') ||
    line.startsWith('#EXT-X-PART') ||
    line.startsWith('#EXT-X-PRELOAD-HINT')
  );
}

function collectSegments(lines, playlistUrl) {
  const segments = [];

  for (const line of lines) {
    if (!line || line.startsWith('#')) continue;
    segments.push({
      index: segments.length,
      url: resolveUrl(playlistUrl, line),
    });
  }

  return segments;
}

function getRootPrefix(playlistUrl, segments) {
  const playlistDirectory = directoryUrl(playlistUrl);
  const firstSegmentUrl = segments[0]?.url;

  if (!firstSegmentUrl) return playlistDirectory;
  if (firstSegmentUrl.startsWith(playlistDirectory)) return playlistDirectory;

  return directoryUrl(firstSegmentUrl);
}

function rewriteMediaPlaylist(lines, playlistUrl) {
  const segments = collectSegments(lines, playlistUrl);
  const rootPrefix = getRootPrefix(playlistUrl, segments);
  const output = [];
  let segmentIndex = 0;
  let pendingSegmentLines = [];
  let pendingExtinf = false;
  let previousWasSkipped = false;
  let outputSegmentCount = 0;
  let hasEndList = false;

  const pushTag = (line) => {
    if (line.startsWith('#EXT-X-MEDIA-SEQUENCE')) {
      output.push('#EXT-X-MEDIA-SEQUENCE:0');
      return;
    }
    output.push(rewriteUriAttributes(line, playlistUrl, '', false));
  };

  for (const line of lines) {
    if (!line) continue;

    if (line === '#EXT-X-ENDLIST') {
      hasEndList = true;
      continue;
    }

    if (line.startsWith('#')) {
      if (isSegmentScopedTag(line) || pendingExtinf) {
        pendingSegmentLines.push(line);
        if (line.startsWith('#EXTINF')) pendingExtinf = true;
      } else {
        pushTag(line);
      }
      continue;
    }

    const segment = segments[segmentIndex];
    segmentIndex += 1;

    if (!segment) {
      pendingSegmentLines = [];
      pendingExtinf = false;
      continue;
    }

    const shouldSkip = !segment.url.startsWith(rootPrefix);
    if (shouldSkip) {
      pendingSegmentLines = [];
      pendingExtinf = false;
      previousWasSkipped = outputSegmentCount > 0;
      continue;
    }

    if (previousWasSkipped && !pendingSegmentLines.some((item) => item.startsWith('#EXT-X-DISCONTINUITY'))) {
      output.push('#EXT-X-DISCONTINUITY');
    }

    for (const pendingLine of pendingSegmentLines) {
      pushTag(pendingLine);
    }

    pendingSegmentLines = [];
    pendingExtinf = false;
    previousWasSkipped = false;
    output.push(segment.url);
    outputSegmentCount += 1;
  }

  if (!outputSegmentCount) {
    throw new Error('All HLS segments were filtered out.');
  }

  if (hasEndList) {
    output.push('#EXT-X-ENDLIST');
  }

  return `${output.join('\n')}\n`;
}

async function getCleanPlaylist(sourceUrl, requestBaseUrl) {
  const normalizedUrl = requireHttpUrl(sourceUrl);
  const cacheKey = `${normalizeBaseUrl(requestBaseUrl)}|${normalizedUrl}`;
  const cached = playlistCache.get(cacheKey);

  if (cached && cached.expiresAt > Date.now()) {
    return cached.body;
  }

  const text = await fetchPlaylistText(normalizedUrl);
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const body = isMasterPlaylist(lines)
    ? rewriteMasterPlaylist(lines, normalizedUrl, requestBaseUrl)
    : rewriteMediaPlaylist(lines, normalizedUrl);

  playlistCache.set(cacheKey, {
    body,
    expiresAt: Date.now() + CACHE_TTL_MS,
  });

  return body;
}

module.exports = {
  createCleanPlaylistUrl,
  getCleanPlaylist,
  getRequestBaseUrl,
  wrapHlsUrl,
  wrapPhimapiLinks,
};
