const axios = require('axios');
const nguoncService = require('../services/nguoncService');

function makeProxyEmbedUrl(url, req) {
    if (!url || typeof url !== 'string') return url;
    const protocol = req.protocol || 'http';
    const host = req.get('host') || 'localhost:3001';
    return `${protocol}://${host}/api/server3/embed-proxy?url=${encodeURIComponent(url)}`;
}

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
            const rawLinks = nguoncService.extractLinksForEpisode(detail.episodes, selectedEpisode);
            const links = {
                vietsub: rawLinks.vietsub ? makeProxyEmbedUrl(rawLinks.vietsub, req) : '',
                dubbed: rawLinks.dubbed ? makeProxyEmbedUrl(rawLinks.dubbed, req) : '',
                m3u8: rawLinks.m3u8 ? makeProxyEmbedUrl(rawLinks.m3u8, req) : ''
            };

            return res.json({ status: 'success', data: { detail, links } });
        }
        res.json({ status: 'not_found' });
    } catch (e) {
        res.status(500).json({ error: 'Server Error', message: e.message });
    }
};

// Extract M3U8 proxy URL from embed URL (server-side extraction, bypasses iframe/player.js)
async function makeProxyM3u8Url(embedUrl, req) {
    if (!embedUrl || typeof embedUrl !== 'string') return '';
    try {
        const parsed = new URL(embedUrl);
        const embedRes = await axios.get(embedUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Referer': 'https://phim.nguonc.com/',
                'Accept': 'text/html',
            },
            timeout: 10000
        });
        const obfMatch = embedRes.data.match(/data-obf="([^"]+)"/);
        if (!obfMatch) return '';
        const streamData = JSON.parse(Buffer.from(obfMatch[1], 'base64').toString('utf-8'));
        if (!streamData.sUb) return '';

        const m3u8Url = `${parsed.origin}/${streamData.sUb}`;
        const protocol = req.protocol || 'http';
        const host = req.get('host') || 'localhost:3001';
        const serverOrigin = `${protocol}://${host}`;
        return `${serverOrigin}/api/server3/proxy?url=${encodeURIComponent(m3u8Url)}&ref=${encodeURIComponent(parsed.origin + '/')}`;
    } catch (e) {
        console.error('[makeProxyM3u8Url Error]:', e.message);
        return '';
    }
}

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
            const rawLinks = nguoncService.extractMovieLinks(detail);
            const links = {
                vietsub: rawLinks.vietsub ? makeProxyEmbedUrl(rawLinks.vietsub, req) : '',
                dubbed: rawLinks.dubbed ? makeProxyEmbedUrl(rawLinks.dubbed, req) : '',
                m3u8: rawLinks.m3u8 ? makeProxyEmbedUrl(rawLinks.m3u8, req) : ''
            };

            return res.json({ status: 'success', data: { detail, links } });
        }

        res.json({ status: 'not_found' });
    } catch (e) {
        res.status(500).json({ error: 'Server Error', message: e.message });
    }
};

// Embed HTML Proxy with Anti-Popup, Cloudflare Bypass & iOS Fix
const embedProxy = async (req, res) => {
    const embedUrl = req.query.url;
    if (!embedUrl) {
        return res.status(400).send('Missing url parameter');
    }

    try {
        const parsed = new URL(embedUrl);
        const embedRes = await axios.get(embedUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
                'Referer': 'https://phim.nguonc.com/',
                'Origin': 'https://phim.nguonc.com',
                'Sec-Ch-Ua': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
            },
            timeout: 10000,
            responseType: 'text'
        });

        let html = embedRes.data;

        // 1. Clean ad scripts, devtool guard, ads.js, and Cloudflare beacon analytics
        html = html.replace(/<script[^>]*_wau[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*ads\.js[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*devtool-guard[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*cloudflareinsights[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*beacon\.min\.js[\s\S]*?<\/script>/gi, '');
        html = html.replace(/_wau\.push\([\s\S]*?\);/gi, '');
        html = html.replace(/onerror="[^"]*blockPlayer[^"]*"/gi, '');
        html = html.replace(/location\.reload\(\)/gi, 'console.log("[Anti-Devtools] Bypassed location.reload")');
        html = html.replace(/typeof\s+devtoolsDetector\s*===\s*["']undefined["']/gi, 'false');

        // 2. Let StreamC detect device natively (isApple = true on iOS/Mac for native HLS, false on Chrome for Hls.js MSE)

        // 3. Neutralize blockPlayer so adblock screen never renders
        html = html.replace(/function\s+blockPlayer\s*\(\)\s*\{[\s\S]*?\}/gi, 'function blockPlayer(){ console.log("[Anti-Adblock] Bypassed blockPlayer call"); }');

        // 4. Inject script: base href + ad/popup bypass + fetch/XHR proxy (needed for CORS)
        // iOS uses native <video> with m3u8Proxy, desktop uses iframe with StreamC's player.js
        // fetch/XHR interceptors are required because iframe is on our domain, not streamc.xyz
        const embedOrigin = parsed.origin;
        const protocol = req.protocol || 'http';
        const host = req.get('host') || 'localhost:3001';
        const serverOrigin = `${protocol}://${host}`;

        const embedScript = `
        <base href="${embedOrigin}/">
        <script>
        (function() {
          const originUrl = "${embedOrigin}";
          const localServerOrigin = "${serverOrigin}";

          window.devtoolsDetector = {
            launch: function() {},
            addListener: function() {},
            isPlugin: false
          };

          function resolveProxyUrl(rawUrl) {
            if (!rawUrl || typeof rawUrl !== 'string') return rawUrl;
            if (rawUrl.includes('/api/server3/proxy')) return rawUrl;
            if (rawUrl.startsWith('blob:') || rawUrl.startsWith('data:') || rawUrl.startsWith('javascript:')) return rawUrl;

            let absUrl = rawUrl;
            if (rawUrl.startsWith('//')) {
              absUrl = 'https:' + rawUrl;
            } else if (rawUrl.startsWith('/')) {
              absUrl = originUrl + rawUrl;
            } else if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) {
              absUrl = originUrl + '/' + rawUrl;
            }

            if (absUrl.includes('jwplayer.com') || absUrl.includes('jwpcdn.com') || absUrl.includes('cloudflare') || absUrl.includes('waust.at') || absUrl.includes('waust.st')) {
              return absUrl;
            }

            var isVideoResource = absUrl.includes('streamc.xyz') || 
                                  absUrl.includes('amass') || 
                                  absUrl.includes('.png') || 
                                  absUrl.includes('.ts') || 
                                  absUrl.includes('.m3u8') || 
                                  absUrl.startsWith(originUrl);

            if (isVideoResource && (absUrl.startsWith('http://') || absUrl.startsWith('https://'))) {
              return localServerOrigin + '/api/server3/proxy?url=' + encodeURIComponent(absUrl) + '&ref=' + encodeURIComponent(originUrl);
            }
            return absUrl;
          }

          // Bypass StreamC popup / adblock checks
          window.popupReady = true;
          window.hasShownAds = true;
          window.playerBlocked = false;

          // Block popups
          window.open = function(url, target, features) {
            console.log('[Anti-Popup] Blocked window.open attempt:', url);
            return null;
          };

          // Intercept fetch to proxy stream requests through our server (CORS bypass)
          if (window.fetch) {
            var rawFetch = window.fetch;
            window.fetch = function() {
              var args = Array.prototype.slice.call(arguments);
              var url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) ? args[0].url : String(args[0]);
              var proxyTarget = resolveProxyUrl(url);
              if (typeof args[0] === 'string') {
                args[0] = proxyTarget;
              }
              return rawFetch.apply(this, args);
            };
          }

          // Intercept XHR to proxy stream requests through our server (CORS bypass)
          if (window.XMLHttpRequest) {
            var rawOpen = window.XMLHttpRequest.prototype.open;
            window.XMLHttpRequest.prototype.open = function(method, url) {
              var proxyTarget = resolveProxyUrl(url);
              var restArgs = Array.prototype.slice.call(arguments, 2);
              return rawOpen.apply(this, [method, proxyTarget].concat(restArgs));
            };
          }

          document.addEventListener('DOMContentLoaded', function() {
            window.popupReady = true;
            window.playerBlocked = false;
            try { window.dispatchEvent(new CustomEvent('popup-ready')); } catch(e) {}
            if (typeof startPlayer === 'function' && !window.playerStarted) {
              startPlayer();
            }
          });
        })();
        </script>
        `;

        if (html.includes('<head>')) {
            html = html.replace('<head>', `<head>${embedScript}`);
        } else {
            html = embedScript + html;
        }

        res.removeHeader('X-Frame-Options');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Content-Security-Policy', "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval' data: blob:; connect-src * data: blob:; img-src * data: blob:; style-src * 'unsafe-inline';");
        res.setHeader('Cache-Control', 'no-store');
        res.send(html);
    } catch (err) {
        console.error('[Embed Proxy Error]:', err.message);
        res.status(500).send('Embed proxy error: ' + err.message);
    }
};

// Stream & Segment Proxy Endpoint
const proxyStream = async (req, res) => {
    const targetUrl = req.query.url;
    const customRef = req.query.ref;
    if (!targetUrl) {
        return res.status(400).send('Missing url parameter');
    }

    try {
        const parsed = new URL(targetUrl);
        let refUrl = customRef ? (customRef.endsWith('/') ? customRef : customRef + '/') : `${parsed.origin}/`;
        let originUrlStr = customRef || parsed.origin;

        if (!customRef && !targetUrl.includes('streamc')) {
            refUrl = 'https://phim.nguonc.com/';
            originUrlStr = 'https://phim.nguonc.com';
        }

        // iOS Safari UA only for StreamC M3U8 WITHOUT ?d=1 (plain M3U8 for native playback)
        // With ?d=1 (desktop player.js expects encrypted M3U8) → keep Chrome UA
        const isStreamcM3u8 = targetUrl.includes('streamc.xyz') && !targetUrl.includes('.png') && !targetUrl.includes('.ts') && !targetUrl.includes('d=1');
        const headers = isStreamcM3u8 ? {
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
            'Accept': '*/*',
            'Referer': refUrl,
        } : {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
            'Referer': refUrl,
            'Origin': originUrlStr,
            'Sec-Ch-Ua': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
        };

        const proxyRes = await axios.get(targetUrl, {
            headers,
            responseType: 'arraybuffer',
            timeout: 15000
        });

        const contentType = proxyRes.headers['content-type'] || 'application/vnd.apple.mpegurl';
        let dataBuf = Buffer.from(proxyRes.data);
        const textContent = dataBuf.toString('utf-8');

        // M3U8 Playlist Rewriter for Native iOS Safari & HLS compatibility (do NOT rewrite encrypted StreamC #ENC-AESGCM payloads)
        if (textContent.includes('#EXTM3U') && !textContent.includes('#ENC-AESGCM')) {
            const protocol = req.protocol || 'http';
            const host = req.get('host') || 'localhost:3001';
            const serverOrigin = `${protocol}://${host}`;

            const lines = textContent.split('\n');
            const rewrittenLines = lines.map(line => {
                const trimmed = line.trim();
                if (!trimmed || trimmed.startsWith('#')) {
                    if (trimmed.includes('URI="')) {
                        return trimmed.replace(/URI="([^"]+)"/g, (match, keyUrl) => {
                            let absKeyUrl = keyUrl;
                            if (keyUrl.startsWith('//')) absKeyUrl = 'https:' + keyUrl;
                            else if (keyUrl.startsWith('/')) absKeyUrl = parsed.origin + keyUrl;
                            else if (!keyUrl.startsWith('http')) absKeyUrl = parsed.origin + '/' + keyUrl;
                            const proxiedKey = `${serverOrigin}/api/server3/proxy?url=${encodeURIComponent(absKeyUrl)}&ref=${encodeURIComponent(refUrl)}`;
                            return `URI="${proxiedKey}"`;
                        });
                    }
                    return line;
                }

                let absSegmentUrl = trimmed;
                if (trimmed.startsWith('//')) {
                    absSegmentUrl = 'https:' + trimmed;
                } else if (trimmed.startsWith('/')) {
                    absSegmentUrl = parsed.origin + trimmed;
                } else if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
                    const baseUrl = targetUrl.substring(0, targetUrl.lastIndexOf('/') + 1);
                    absSegmentUrl = baseUrl + trimmed;
                }

                return `${serverOrigin}/api/server3/proxy?url=${encodeURIComponent(absSegmentUrl)}&ref=${encodeURIComponent(refUrl)}`;
            });

            dataBuf = Buffer.from(rewrittenLines.join('\n'), 'utf-8');
        }

        res.setHeader('Content-Type', contentType);
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Cache-Control', 'no-store');
        res.send(dataBuf);
    } catch (err) {
        console.error('[Stream Proxy Error]:', err.message);
        res.status(err.response?.status || 500).send('Stream proxy error: ' + err.message);
    }
};

// Stream URL Extractor - bypasses StreamC iframe/player.js entirely
// Extracts M3U8 URL from embed page, returns proxied M3U8 URL for direct native playback
const streamUrl = async (req, res) => {
    const embedUrl = req.query.url;
    if (!embedUrl) {
        return res.status(400).json({ error: 'Missing url parameter' });
    }

    try {
        const parsed = new URL(embedUrl);
        
        // 1. Fetch embed page to extract data-obf
        const embedRes = await axios.get(embedUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'Referer': 'https://phim.nguonc.com/',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            },
            timeout: 10000
        });

        const html = embedRes.data;
        
        // 2. Extract data-obf from <div id="player" data-obf="...">
        const obfMatch = html.match(/data-obf="([^"]+)"/);
        if (!obfMatch) {
            return res.status(404).json({ error: 'Stream data not found' });
        }

        // 3. Decode base64 to get stream token
        const streamData = JSON.parse(Buffer.from(obfMatch[1], 'base64').toString('utf-8'));
        if (!streamData.sUb) {
            return res.status(404).json({ error: 'Stream token not found' });
        }

        // 4. Build proxied M3U8 URL (without ?d=1 for plain M3U8, same as iOS on nguonc.com)
        const m3u8Url = `${parsed.origin}/${streamData.sUb}`;
        const protocol = req.protocol || 'http';
        const host = req.get('host') || 'localhost:3001';
        const serverOrigin = `${protocol}://${host}`;
        const proxiedM3u8 = `${serverOrigin}/api/server3/proxy?url=${encodeURIComponent(m3u8Url)}&ref=${encodeURIComponent(parsed.origin + '/')}`;

        res.json({
            status: 'success',
            m3u8: proxiedM3u8,
            origin: parsed.origin
        });
    } catch (err) {
        console.error('[StreamUrl Error]:', err.message);
        res.status(500).json({ error: 'Stream extraction failed', message: err.message });
    }
};

module.exports = {
    searchTVShow,
    searchMovie,
    embedProxy,
    proxyStream,
    streamUrl
};
