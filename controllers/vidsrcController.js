const mongoose = require('mongoose');
const axios = require('axios');

// In-memory cache for OpenSubtitles search results to prevent Render IP rate limits
const subSearchCache = new Map();
const SUB_CACHE_TTL = 6 * 60 * 60 * 1000; // 6 hours

// Controller: Simply return the active VidSrc domain configured by Django Admin
const getActiveDomain = async (req, res) => {
    try {
        const db = mongoose.connection.db;
        if (db) {
            const settings = await db.collection('systemsettings').findOne({ key: 'vidsrc_config' });
            if (settings && settings.active_domain) {
                return res.json({
                    ok: true,
                    active_domain: settings.active_domain,
                    auto_update: settings.auto_update || false
                });
            }
        }
        return res.json({ ok: true, active_domain: '' });
    } catch (error) {
        console.error('Error reading active vidsrc domain:', error);
        return res.json({ ok: false, error: error.message });
    }
};

const VIDSRC_WHITELIST_PATTERN = /(?:localhost|127\.0\.0\.1|vidsrcme\.su|vidsrc\.[a-z0-9-]+|cloudorchestranova\.com|vidsrcme\.ru|vidapi\.cloud|comityofcognomen\.site|epexegesisengine\.site|propinquitypostulate\.website|ataraxiaoftheapex\.space|\.site|\.website|\.space|\.online|\.tech|\.store|\.fun|\.xyz|\.top|\.live|\.stream|\.cloud|tmdb\.org|themoviedb\.org|opensubtitles\.org|opensubtitles\.com|jwplayer\.com|jwpcdn\.com|cloudflare\.com|jsdelivr\.net)/i;

// VidSrc Embed Proxy (Ad-blocking, Whitelist, Referer Bypassing)
const embedProxy = async (req, res) => {
    const embedUrl = req.query.url;
    if (!embedUrl) {
        return res.status(400).send('Missing url parameter');
    }

    if (embedUrl.includes('about:blank') || embedUrl.startsWith('about:')) {
        return res.status(200).send('<html><body></body></html>');
    }

    try {
        // Automatically rewrite Level 1 alternate VidSrc domains (vidsrc.bz, vidsrc.me, vidsrc.io...) to vidsrcme.su (the primary domain that returns 200 OK)
        let targetEmbedUrl = embedUrl;
        if (targetEmbedUrl.includes('/embed/movie') || targetEmbedUrl.includes('/embed/tv')) {
            targetEmbedUrl = targetEmbedUrl.replace(/https?:\/\/(?:vidsrc\.[a-z0-9-]+|vidsrcme\.su)/i, 'https://vidsrcme.su');
        }

        const parsed = new URL(targetEmbedUrl);

        const customRef = req.query.ref;
        let refererHeader = customRef ? (customRef.endsWith('/') ? customRef : customRef + '/') : `${parsed.origin}/`;
        if (targetEmbedUrl.includes('cloudorchestranova.com/embed/movie') || targetEmbedUrl.includes('cloudorchestranova.com/embed/tv')) {
            refererHeader = 'https://vidsrcme.su/';
        } else if (targetEmbedUrl.includes('cloudorchestranova.com/embed/player')) {
            refererHeader = 'https://cloudorchestranova.com/';
        }

        console.log(`[vidsrc-embed-proxy] 🌐 Fetching embed: ${targetEmbedUrl}`);
        console.log(`[vidsrc-embed-proxy] 🔑 Using Referer: ${refererHeader}`);

        const embedRes = await axios.get(targetEmbedUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
                'Referer': refererHeader,
                'Origin': parsed.origin,
                'Sec-Ch-Ua': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
            },
            timeout: 10000,
            responseType: 'text'
        });

        console.log(`[vidsrc-embed-proxy] ✅ Response (200 OK) for: ${targetEmbedUrl}`);
        let html = embedRes.data;

        // Clean known ad scripts & devtool killers
        html = html.replace(/<script[^>]*ads\.js[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*devtool-guard[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*disable-devtool[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*no-devtool[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*beacon\.min\.js[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*adexchangerapid[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*canoesaisles[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*groszynudgepreter[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*glumsynemasmitham[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*histats[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*waust[\s\S]*?<\/script>/gi, '');
        html = html.replace(/location\.replace\(['"]about:blank['"]\)/gi, 'console.log("[Anti-Devtools] Bypassed about:blank")');
        html = html.replace(/document\.documentElement\.innerHTML\s*=\s*['"]['"]/gi, 'console.log("[Anti-Devtools] Bypassed innerHTML clear")');
        html = html.replace(/DisableDevtool/gi, 'NoDevtool');
        html = html.replace(/disable-devtool/gi, 'no-devtool');
        html = html.replace(/histats/gi, 'nohistats');
        html = html.replace(/VS_DEVTOOLS/g, 'NO_DEVTOOLS');
        html = html.replace(/VS_EXPIRED/g, 'NO_EXPIRED');

        const embedOrigin = parsed.origin;
        const rawProto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').toString();
        const host = req.get('host') || 'localhost:3001';
        const protocol = (rawProto.includes('https') || host.includes('onrender.com')) ? 'https' : 'http';
        const serverOrigin = `${protocol}://${host}`;

        const monitorScript = `
        <base href="${embedOrigin}/">
        <script>
        (function() {
          const originUrl = "${embedOrigin}";
          const localServerOrigin = "${serverOrigin}";
          const VIDSRC_WHITELIST_PATTERN = /(?:localhost|127\\.0\\.0\\.1|vidsrcme\\.su|vidsrc\\.me|vidsrc\\.in|vidsrc\\.pm|vidsrc\\.net|vidsrc\\.xyz|vidsrc\\.io|vidsrc\\.cc|vidsrc\\.to|cloudorchestranova\\.com|vidsrcme\\.ru|vidapi\\.cloud|comityofcognomen\\.site|epexegesisengine\\.site|propinquitypostulate\\.website|ataraxiaoftheapex\\.space|\\.site|\\.website|\\.space|\\.online|\\.tech|\\.store|\\.fun|\\.xyz|\\.top|\\.live|\\.stream|\\.cloud|tmdb\\.org|themoviedb\\.org|opensubtitles\\.org|opensubtitles\\.com|jwplayer\\.com|jwpcdn\\.com|cloudflare\\.com|jsdelivr\\.net)/i;

          window.DisableDevtool = function() {};
          window.NoDevtool = function() {};
          window.devtoolsDetector = { launch: function() {}, addListener: function() {}, isPlugin: false };

          function isAllowedDomain(urlStr) {
            if (!urlStr || typeof urlStr !== 'string') return true;
            if (urlStr.startsWith('blob:') || urlStr.startsWith('data:') || urlStr.startsWith('javascript:') || urlStr.startsWith('about:')) return true;
            const lower = urlStr.toLowerCase();
            if (lower.includes('/pl/') || lower.includes('.m3u8') || lower.includes('.ts') || lower.includes('.vtt') || lower.includes('.key') || lower.includes('.wasm') || lower.includes('.woff') || lower.includes('.woff2') || lower.includes('.ttf') || lower.includes('.js') || lower.includes('.css') || lower.includes('.json') || lower.includes('wasm.php') || lower.includes('api.php') || lower.includes('/embed/') || lower.includes('/player/') || lower.includes('/src/') || lower.includes('generate.php')) {
              return true;
            }
            try {
              const u = new URL(urlStr, window.location.href);
              const h = u.hostname.toLowerCase();
              if (h.endsWith('.site') || h.endsWith('.website') || h.endsWith('.space') || h.endsWith('.online') || h.endsWith('.tech') || h.endsWith('.store') || h.endsWith('.fun') || h.endsWith('.xyz') || h.endsWith('.top') || h.endsWith('.live') || h.endsWith('.stream') || h.endsWith('.cloud')) {
                return true;
              }
              return VIDSRC_WHITELIST_PATTERN.test(u.hostname);
            } catch(e) {
              return true;
            }
          }

          function resolveEmbedProxyUrl(rawUrl) {
            if (!rawUrl || typeof rawUrl !== 'string') return rawUrl;
            if (rawUrl.includes('/api/vidsrc/embed-proxy')) return rawUrl;
            if (rawUrl.startsWith('blob:') || rawUrl.startsWith('data:') || rawUrl.startsWith('javascript:') || rawUrl.startsWith('about:')) return rawUrl;

            let absUrl = rawUrl;
            if (rawUrl.startsWith('//')) absUrl = 'https:' + rawUrl;
            else if (rawUrl.startsWith('/')) absUrl = originUrl + rawUrl;
            else if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) absUrl = originUrl + '/' + rawUrl;

            return localServerOrigin + '/api/vidsrc/embed-proxy?url=' + encodeURIComponent(absUrl) + '&ref=' + encodeURIComponent(originUrl);
          }

          try {
            const origIframeSrcDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
            if (origIframeSrcDesc && origIframeSrcDesc.set) {
              Object.defineProperty(HTMLIFrameElement.prototype, 'src', {
                get: origIframeSrcDesc.get,
                set: function(val) {
                  const proxyTarget = resolveEmbedProxyUrl(val);
                  return origIframeSrcDesc.set.call(this, proxyTarget);
                }
              });
            }
            const origSetAttr = HTMLIFrameElement.prototype.setAttribute;
            HTMLIFrameElement.prototype.setAttribute = function(name, val) {
              if (String(name).toLowerCase() === 'src') {
                val = resolveEmbedProxyUrl(val);
              }
              return origSetAttr.call(this, name, val);
            };
          } catch(e) {}

          const rawAddEventListener = window.addEventListener;
          window.addEventListener = function(type, listener, options) {
            if (type === 'message' && typeof listener === 'function') {
              const safeListener = function(e) {
                if (e && e.data) {
                  if (e.data.type === 'VS_DEVTOOLS' || e.data.type === 'VS_EXPIRED') {
                    return;
                  }
                }
                return listener.call(this, e);
              };
              return rawAddEventListener.call(this, type, safeListener, options);
            }
            return rawAddEventListener.call(this, type, listener, options);
          };

          function resolveProxyUrl(rawUrl) {
            if (!rawUrl || typeof rawUrl !== 'string') return rawUrl;
            if (rawUrl.includes('/api/vidsrc/proxy')) return rawUrl;
            if (rawUrl.startsWith('blob:') || rawUrl.startsWith('data:') || rawUrl.startsWith('javascript:') || rawUrl.startsWith('about:')) return rawUrl;

            let absUrl = rawUrl;
            if (rawUrl.startsWith('//')) absUrl = 'https:' + rawUrl;
            else if (rawUrl.startsWith('/')) absUrl = originUrl + rawUrl;
            else if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) absUrl = originUrl + '/' + rawUrl;

            if (!isAllowedDomain(absUrl)) {
              return 'data:text/javascript,/*blocked_by_whitelist*/';
            }

            if (absUrl.includes('jwplayer.com') || absUrl.includes('jwpcdn.com') || absUrl.includes('cloudflare.com') || absUrl.includes('jsdelivr.net')) return absUrl;

            // Intercept local relative M3U8 requests like http://localhost:3001/pl/...
            if (absUrl.includes(window.location.host) && absUrl.includes('/pl/')) {
              const realPath = absUrl.substring(absUrl.indexOf('/pl/'));
              const realTarget = 'https://comityofcognomen.site' + realPath;
              return localServerOrigin + '/api/vidsrc/proxy?url=' + encodeURIComponent(realTarget) + '&ref=https%3A%2F%2Fcloudorchestranova.com';
            }

            if (absUrl.startsWith('http://') || absUrl.startsWith('https://')) {
              return localServerOrigin + '/api/vidsrc/proxy?url=' + encodeURIComponent(absUrl) + '&ref=' + encodeURIComponent(originUrl);
            }
            return absUrl;
          }

          window.open = function(url, target, features) {
            console.log('[Anti-Popup VidSrc] Blocked window.open attempt:', url);
            return { focus: function() {}, blur: function() {}, close: function() {}, postMessage: function() {} };
          };

          try {
            const origCreateElement = document.createElement;
            document.createElement = function(tagName, options) {
              const el = origCreateElement.call(this, tagName, options);
              if (String(tagName).toLowerCase() === 'a') {
                const origClick = el.click;
                el.click = function() {
                  if (el.target === '_blank' || !isAllowedDomain(el.href)) {
                    console.log('[Anti-Adblock VidSrc] Whitelist blocked fake link click:', el.href);
                    return;
                  }
                  return origClick.call(this);
                };
              }
              return el;
            };
          } catch(e) {}

          document.addEventListener('click', function(e) {
            let el = e.target;
            while (el && el !== document) {
              if (el.tagName === 'A' && el.href) {
                if (el.target === '_blank' || !isAllowedDomain(el.href)) {
                  e.preventDefault();
                  e.stopPropagation();
                  console.log('[Anti-Adblock VidSrc] Whitelist intercepted click ad navigation:', el.href);
                  return false;
                }
              }
              el = el.parentElement;
            }
          }, true);

          if (window.fetch) {
            const rawFetch = window.fetch;
            window.fetch = async function(input, init) {
              let url = '';
              if (typeof input === 'string') {
                url = input;
              } else if (input && typeof input === 'object' && input.url) {
                url = input.url;
              } else {
                url = String(input);
              }

              const proxyTarget = resolveProxyUrl(url);

              if (typeof input === 'string') {
                return rawFetch.call(this, proxyTarget, init);
              } else if (input && typeof input === 'object' && input.url) {
                try {
                  const newReq = new Request(proxyTarget, input);
                  return rawFetch.call(this, newReq, init);
                } catch(e) {
                  return rawFetch.call(this, proxyTarget, init || input);
                }
              }
              return rawFetch.call(this, proxyTarget, init);
            };
          }

          if (window.XMLHttpRequest) {
            const rawOpen = window.XMLHttpRequest.prototype.open;
            window.XMLHttpRequest.prototype.open = function(method, url) {
              const proxyTarget = resolveProxyUrl(url);
              const restArgs = Array.prototype.slice.call(arguments, 2);
              return rawOpen.apply(this, [method, proxyTarget].concat(restArgs));
            };
          }

          // iOS Safari native HLS: intercept video.src and source.src so that
          // M3U8 URLs go through the proxy (which adds correct Referer/Origin
          // and rewrites segment URLs). Without this, iOS AVPlayer requests CDN
          // URLs directly with the proxy domain as Referer, causing the CDN to
          // reject the request.
          try {
            const vidSrcDesc = Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'src')
                            || Object.getOwnPropertyDescriptor(HTMLVideoElement.prototype, 'src');
            if (vidSrcDesc && vidSrcDesc.set) {
              Object.defineProperty(HTMLMediaElement.prototype, 'src', {
                get: vidSrcDesc.get,
                set: function(val) {
                  if (val && typeof val === 'string' && (val.includes('.m3u8') || val.includes('/pl/'))) {
                    val = resolveProxyUrl(val);
                  }
                  return vidSrcDesc.set.call(this, val);
                },
                configurable: true
              });
            }
            // Also intercept setAttribute('src', ...) on video elements
            const origVidSetAttr = HTMLMediaElement.prototype.setAttribute;
            HTMLMediaElement.prototype.setAttribute = function(name, val) {
              if (String(name).toLowerCase() === 'src' && val && typeof val === 'string' && (val.includes('.m3u8') || val.includes('/pl/'))) {
                val = resolveProxyUrl(val);
              }
              return origVidSetAttr.call(this, name, val);
            };
          } catch(e) {}

          // ═══════════════════════════════════════════════════════════════
          // Auto-trigger subtitle loading: Hook into JWSubs.setup so
          // auto() runs immediately after player receives IMDB ID from API
          // ═══════════════════════════════════════════════════════════════
          var _hookedSetup = false;
          function hookJWSubs() {
            if (window.JWSubs && window.JWSubs.setup && !_hookedSetup) {
              _hookedSetup = true;
              var origSetup = window.JWSubs.setup;
              window.JWSubs.setup = function(data) {
                var res = origSetup.apply(this, arguments);
                setTimeout(function() {
                  try {
                    if (window.JWSubs && typeof window.JWSubs.auto === 'function') {
                      window.JWSubs.auto();
                    }
                  } catch(e) {}
                }, 300);
                return res;
              };
            }
            if (window.JWSubs && typeof window.JWSubs.auto === 'function') {
              try { window.JWSubs.auto(); } catch(e) {}
            }
          }
          var _hookInterval = setInterval(hookJWSubs, 1000);
          setTimeout(function() { clearInterval(_hookInterval); }, 15000);
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
        const statusCode = err.response ? err.response.status : 500;
        console.error(`[vidsrc-embed-proxy] ❌ Error (${statusCode}) for ${embedUrl}:`, err.message);
        if (err.response) {
            console.error(`[vidsrc-embed-proxy] Status Details: ${err.response.status} ${err.response.statusText}`);
        }
        res.status(statusCode).send('VidSrc embed proxy error: ' + err.message);
    }
};

// VidSrc Stream Proxy
const proxyStream = async (req, res) => {
    const targetUrl = req.query.url;
    const customRef = req.query.ref;
    if (!targetUrl) {
        return res.status(400).send('Missing url parameter');
    }

    // OpenSubtitles search caching (prevents Render IP rate-limiting)
    if (targetUrl.includes('opensubtitles.org/search/')) {
        const cached = subSearchCache.get(targetUrl);
        if (cached && (Date.now() - cached.time < SUB_CACHE_TTL)) {
            res.setHeader('Content-Type', cached.contentType);
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.setHeader('Cache-Control', 'public, max-age=21600');
            return res.send(cached.data);
        }
    }

    try {
        const parsed = new URL(targetUrl);
        const lowerUrl = targetUrl.toLowerCase();
        const lowerHost = parsed.hostname.toLowerCase();

        const isStreamResource = lowerUrl.includes('/pl/') || 
                                 lowerUrl.includes('.m3u8') || 
                                 lowerUrl.includes('.ts') || 
                                 lowerUrl.includes('.vtt') || 
                                 lowerUrl.includes('.srt') || 
                                 lowerUrl.includes('/subtitles/') || 
                                 lowerUrl.includes('/sub/') || 
                                 lowerUrl.includes('opensubtitles') || 
                                 lowerUrl.includes('.key') || 
                                 lowerUrl.includes('.wasm') || 
                                 lowerUrl.includes('.woff') || 
                                 lowerUrl.includes('.woff2') || 
                                 lowerUrl.includes('.ttf') || 
                                 lowerUrl.includes('.js') || 
                                 lowerUrl.includes('.css') || 
                                 lowerUrl.includes('.json') || 
                                 lowerUrl.includes('wasm.php') || 
                                 lowerUrl.includes('api.php') || 
                                 lowerUrl.includes('/embed/') || 
                                 lowerUrl.includes('/player/') || 
                                 lowerUrl.includes('/src/') || 
                                 lowerUrl.includes('vs_src.php') || 
                                 lowerUrl.includes('generate.php') || 
                                 lowerHost.endsWith('.site') || 
                                 lowerHost.endsWith('.website') || 
                                 lowerHost.endsWith('.space') || 
                                 lowerHost.endsWith('.online') || 
                                 lowerHost.endsWith('.tech') || 
                                 lowerHost.endsWith('.store') || 
                                 lowerHost.endsWith('.fun') || 
                                 lowerHost.endsWith('.xyz') || 
                                 lowerHost.endsWith('.top') || 
                                 lowerHost.endsWith('.live') || 
                                 lowerHost.endsWith('.stream') || 
                                 lowerHost.endsWith('.cloud');

        if (!isStreamResource && !VIDSRC_WHITELIST_PATTERN.test(parsed.hostname)) {
            console.log(`[vidsrc-proxy] 🛡️ Whitelist blocked ad domain: ${parsed.hostname}`);
            res.setHeader('Content-Type', 'application/javascript');
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.setHeader('Cache-Control', 'no-store');
            return res.send('/* Blocked by Whitelist proxy */');
        }

        let refUrl = customRef ? (customRef.endsWith('/') ? customRef : customRef + '/') : `${parsed.origin}/`;
        let originUrlStr = customRef || parsed.origin;

        if (targetUrl.includes('cloudorchestranova.com') || targetUrl.includes('vidsrcme.ru') || targetUrl.includes('vidapi.cloud') || isStreamResource) {
            refUrl = 'https://cloudorchestranova.com/';
            originUrlStr = 'https://cloudorchestranova.com';
        }

        if (targetUrl.includes('opensubtitles') || targetUrl.includes('cache.php') || targetUrl.includes('.vtt') || targetUrl.includes('subtitles.js')) {
            console.log(`[vidsrc-proxy] 🎬 Subtitle Resource (${req.method}): ${targetUrl}`);
        }

        const passHeaders = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
            'Referer': refUrl,
            'Origin': originUrlStr,
            'Sec-Ch-Ua': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'cross-site'
        };

        if (targetUrl.includes('opensubtitles')) {
            passHeaders['X-User-Agent'] = req.headers['x-user-agent'] || 'trailers.to-UA';
        }

        if (req.headers['content-type']) {
            passHeaders['Content-Type'] = req.headers['content-type'];
        }

        if (req.headers['range']) {
            passHeaders['Range'] = req.headers['range'];
        }

        const axiosConfig = {
            method: req.method || 'GET',
            url: targetUrl,
            headers: passHeaders,
            responseType: 'arraybuffer',
            timeout: 15000,
            validateStatus: () => true
        };

        // Forward request body for POST/PUT requests (needed for cache.php & cache-vtt.php binary payloads)
        if (req.method && req.method !== 'GET' && req.method !== 'HEAD') {
            let bodyBuffer = null;
            if (Buffer.isBuffer(req.body)) {
                bodyBuffer = req.body;
            } else if (typeof req.body === 'string') {
                bodyBuffer = Buffer.from(req.body);
            } else if (typeof req.body === 'object' && req.body !== null && Object.keys(req.body).length > 0) {
                const querystring = require('querystring');
                bodyBuffer = Buffer.from(querystring.stringify(req.body));
            }

            // If Express didn't parse binary payload (e.g. application/octet-stream), read raw stream
            if (!bodyBuffer || bodyBuffer.length === 0) {
                bodyBuffer = await new Promise((resolve) => {
                    const chunks = [];
                    req.on('data', chunk => chunks.push(chunk));
                    req.on('end', () => resolve(Buffer.concat(chunks)));
                    req.on('error', () => resolve(null));
                });
            }

            if (bodyBuffer && bodyBuffer.length > 0) {
                axiosConfig.data = bodyBuffer;
            }
        }

        const proxyRes = await axios(axiosConfig);

        let contentType = proxyRes.headers['content-type'] || 'application/octet-stream';
        if (targetUrl.includes('opensubtitles') && contentType.includes('text/html')) {
            contentType = 'application/json; charset=utf-8';
        }

        let dataBuf = Buffer.from(proxyRes.data);
        const textContent = dataBuf.toString('utf-8');

        // Patch subtitles.js on-the-fly to filter unsupported .ass/.sub formats and auto-retry next OpenSubtitles result on error
        if (targetUrl.includes('subtitles.js')) {
            let jsText = textContent;
            jsText = jsText.replace(
                "searchOS(lang).then(function (data) {",
                `searchOS(lang).then(function (data) {
        if (Array.isArray(data)) {
            data = data.filter(function(s) {
                var fn = (s.SubFileName || s.MovieReleaseName || s.SubFormat || '').toLowerCase();
                return !fn.endsWith('.ass') && !fn.endsWith('.sub') && !fn.endsWith('.idx') && s.SubFormat !== 'ass' && s.SubFormat !== 'sub';
            });
        }`
            ).replace(
                "resolveVtt(sub).then(function (url) {",
                `resolveVtt(sub).then(function (url) {
            if (!url && idx + 1 < SUB.results.length) {
                loadResult(idx + 1, silent);
                return;
            }`
            );
            dataBuf = Buffer.from(jsText, 'utf-8');
        }

        // M3U8 Playlist Rewriter
        if (textContent.includes('#EXTM3U')) {
            const rawProto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').toString();
            const host = req.get('host') || 'localhost:3001';
            const protocol = (rawProto.includes('https') || host.includes('onrender.com')) ? 'https' : 'http';
            const serverOrigin = `${protocol}://${host}`;
            const targetBaseUrl = targetUrl.substring(0, targetUrl.lastIndexOf('/') + 1);

            const lines = textContent.split('\n');
            const rewrittenLines = lines.map((line) => {
                const trimmed = line.trim();
                if (!trimmed || trimmed.startsWith('#')) {
                    if (trimmed.includes('URI="')) {
                        return trimmed.replace(/URI="([^"]+)"/g, (match, keyUrl) => {
                            let absKeyUrl = keyUrl;
                            if (keyUrl.startsWith('//')) absKeyUrl = 'https:' + keyUrl;
                            else if (keyUrl.startsWith('/')) absKeyUrl = parsed.origin + keyUrl;
                            else if (!keyUrl.startsWith('http')) absKeyUrl = targetBaseUrl + keyUrl;
                            const proxiedKey = `${serverOrigin}/api/vidsrc/proxy?url=${encodeURIComponent(absKeyUrl)}&ref=${encodeURIComponent(refUrl)}`;
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
                    absSegmentUrl = targetBaseUrl + trimmed;
                }

                return `${serverOrigin}/api/vidsrc/proxy?url=${encodeURIComponent(absSegmentUrl)}&ref=${encodeURIComponent(refUrl)}`;
            });

            dataBuf = Buffer.from(rewrittenLines.join('\n'), 'utf-8');
        }

        res.setHeader('Content-Type', contentType);
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', '*');
        res.setHeader('Accept-Ranges', 'bytes');
        res.setHeader('Cache-Control', 'no-store');

        if (targetUrl.includes('opensubtitles.org/search/') && proxyRes.status === 200 && dataBuf.length > 2) {
            subSearchCache.set(targetUrl, {
                data: dataBuf,
                contentType: contentType,
                time: Date.now()
            });
        }

        res.status(proxyRes.status).send(dataBuf);
    } catch (err) {
        const statusCode = err.response ? err.response.status : 500;
        console.error(`[vidsrc-proxy] ❌ Error (${statusCode}) for ${targetUrl}:`, err.message);
        if (err.response) {
            console.error(`[vidsrc-proxy] Status Details: ${err.response.status} ${err.response.statusText}`);
        }
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', '*');
        res.status(statusCode).send('VidSrc stream proxy error: ' + err.message);
    }
};

module.exports = {
    getActiveDomain,
    embedProxy,
    proxyStream
};
