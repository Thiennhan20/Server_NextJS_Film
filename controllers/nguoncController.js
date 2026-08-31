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

        // 2. Force isApple = false so StreamC constructs streamURL with ?d=1 for JWPlayer
        html = html.replace(/isApple\s*=\s*isIOS\s*\|\|\s*isMac/gi, 'isApple = false');

        // 3. Neutralize blockPlayer so adblock screen never renders
        html = html.replace(/function\s+blockPlayer\s*\(\)\s*\{[\s\S]*?\}/gi, 'function blockPlayer(){ console.log("[Anti-Adblock] Bypassed blockPlayer call"); }');

        // 4. Inject monitorScript & proxy re-router
        const embedOrigin = parsed.origin;
        const protocol = req.protocol || 'http';
        const host = req.get('host') || 'localhost:3001';
        const serverOrigin = `${protocol}://${host}`;

        const monitorScript = `
        <base href="${embedOrigin}/">
        <script>
        (function() {
          const originUrl = "${embedOrigin}";
          const localServerOrigin = "${serverOrigin}";

          function resolveProxyUrl(rawUrl) {
            if (!rawUrl || typeof rawUrl !== 'string') return rawUrl;
            if (rawUrl.includes('/api/server3/proxy')) return rawUrl;

            // 1. NEVER touch or prepend origin to blob:, data:, or javascript: URLs
            if (rawUrl.startsWith('blob:') || rawUrl.startsWith('data:') || rawUrl.startsWith('javascript:')) {
              return rawUrl;
            }

            // 2. Convert protocol-relative // to https:// first
            let absUrl = rawUrl;
            if (rawUrl.startsWith('//')) {
              absUrl = 'https:' + rawUrl;
            } else if (rawUrl.startsWith('/')) {
              absUrl = originUrl + rawUrl;
            } else if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) {
              absUrl = originUrl + '/' + rawUrl;
            }

            // 3. Do NOT proxy official CDNs like JWPlayer, Cloudflare, or analytics
            if (absUrl.includes('jwplayer.com') || absUrl.includes('jwpcdn.com') || absUrl.includes('cloudflare') || absUrl.includes('waust.at') || absUrl.includes('waust.st')) {
              return absUrl;
            }

            // 4. Proxy stream endpoints, CDN segment domains (amass, streamc.xyz), and video segment files (.png, .ts, .m3u8)
            const isVideoResource = absUrl.includes('streamc.xyz') || 
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

          // Override Navigator properties on iOS so StreamC player.js uses Hls.js MSE instead of native Safari video src=blob
          try {
            Object.defineProperty(navigator, 'userAgent', { get: function() { return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'; } });
            Object.defineProperty(navigator, 'platform', { get: function() { return 'Win32'; } });
            Object.defineProperty(navigator, 'maxTouchPoints', { get: function() { return 0; } });
          } catch(e) {}

          // Override window.open to block popups & new tabs
          window.open = function(url, target, features) {
            console.log('[Anti-Popup] Blocked window.open attempt:', url);
            return null;
          };

          // Intercept fetch and reroute relative/remote stream URLs through local proxy
          if (window.fetch) {
            const rawFetch = window.fetch;
            window.fetch = async function(...args) {
              const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) ? args[0].url : String(args[0]);
              const proxyTarget = resolveProxyUrl(url);

              if (typeof args[0] === 'string') {
                args[0] = proxyTarget;
              } else if (args[0] && typeof args[0] === 'object') {
                try {
                  args[0] = new Request(proxyTarget, args[0]);
                } catch(e) {
                  args[0] = proxyTarget;
                }
              }

              return rawFetch.apply(this, args);
            };
          }

          // Intercept XHR and reroute relative/remote stream URLs through local proxy
          if (window.XMLHttpRequest) {
            const rawOpen = window.XMLHttpRequest.prototype.open;
            window.XMLHttpRequest.prototype.open = function(method, url) {
              const proxyTarget = resolveProxyUrl(url);
              const restArgs = Array.prototype.slice.call(arguments, 2);
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
            html = html.replace('<head>', `<head>${monitorScript}`);
        } else {
            html = monitorScript + html;
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

        const proxyRes = await axios.get(targetUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'Accept': '*/*',
                'Accept-Language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
                'Referer': refUrl,
                'Origin': originUrlStr,
                'Sec-Ch-Ua': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
            },
            responseType: 'arraybuffer',
            timeout: 15000
        });

        const contentType = proxyRes.headers['content-type'] || 'application/vnd.apple.mpegurl';
        res.setHeader('Content-Type', contentType);
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Cache-Control', 'no-store');
        res.send(Buffer.from(proxyRes.data));
    } catch (err) {
        console.error('[Stream Proxy Error]:', err.message);
        res.status(err.response?.status || 500).send('Stream proxy error: ' + err.message);
    }
};

module.exports = {
    searchTVShow,
    searchMovie,
    embedProxy,
    proxyStream
};
