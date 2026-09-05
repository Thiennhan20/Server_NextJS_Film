const mongoose = require('mongoose');

// Controller: Simply return the active VidSrc domain configured by Django Admin
const getActiveDomain = async (req, res) => {
    try {
        const db = mongoose.connection.db;
        if (db) {
            const settings = await db.collection('systemsettings').findOne({ key: 'vidsrc_config' });
            if (settings && settings.active_domain) {
                let domain = settings.active_domain;
                if (domain.includes('vidsrc-me.ru') || domain.includes('vidsrcme.ru')) {
                    domain = 'https://vidsrcme.su';
                }
                return res.json({
                    ok: true,
                    active_domain: domain,
                    auto_update: settings.auto_update || false
                });
            }
        }
        return res.json({ ok: true, active_domain: 'https://vidsrcme.su' });
    } catch (error) {
        console.error('Error fetching active VidSrc domain:', error);
        return res.status(500).json({ ok: false, message: 'Internal Server Error' });
    }
};

const VIDSRC_WHITELIST_PATTERN = /(?:localhost|127\.0\.0\.1|vidsrcme\.su|vidsrc\.[a-z0-9-]+|cloudorchestranova\.com|vidsrcme\.ru|vidapi\.cloud|comityofcognomen\.site|epexegesisengine\.site|propinquitypostulate\.website|ataraxiaoftheapex\.space|zenithofzircon\.space|onomatopoeiaoverture\.website|vercel\.app|onrender\.com|\.(?:site|website|space|online|tech|store|fun|xyz|top|live|stream|cloud|pro|cc|vip|icu|cfd|sbs|bond|lat|best|mom|pw|me|tv|ws|click|link|info|biz|asia|one|today|rest|download|video|movie|run|app|is|to|io|co|club|work|world|moe|su|ru|sh|li|cx|ag|la|vc|bz|vg|ms|gs|tc|ac|im|gg|in|pm|ai|mobi|nu)|tmdb\.org|themoviedb\.org|opensubtitles\.org|opensubtitles\.com|subscene\.com|osdb\.link|subdl\.com|statically\.io|cloudfront\.net|fastly\.net|jwplayer\.com|jwpcdn\.com|cloudflare\.com|jsdelivr\.net)/i;
const STREAM_TLD_REGEX = /\.(?:site|website|space|online|tech|store|fun|xyz|top|live|stream|cloud|pro|cc|vip|icu|cfd|sbs|bond|lat|best|mom|pw|me|tv|ws|click|link|info|biz|asia|one|today|rest|download|video|movie|run|app|is|to|io|co|club|work|world|moe|su|ru|sh|li|cx|ag|la|vc|bz|vg|ms|gs|tc|ac|im|gg|in|pm|ai|mobi|nu)$/i;

async function fetchWithTimeout(resource, options = {}) {
    const { timeout = 15000 } = options;
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
        const response = await fetch(resource, {
            ...options,
            signal: controller.signal
        });
        clearTimeout(id);
        return response;
    } catch (error) {
        clearTimeout(id);
        throw error;
    }
}

// VidSrc Embed Proxy (Ad-blocking, Whitelist, Anti-Popup, Referer Bypassing)
const embedProxy = async (req, res) => {
    const embedUrl = req.query.url;
    if (!embedUrl) {
        return res.status(400).send('Missing url parameter');
    }

    try {
        const parsed = new URL(embedUrl);
        console.log(`[vidsrc-embed-proxy] Fetching embed HTML: ${embedUrl}`);
        let refererHeader = `${parsed.origin}/`;
        const customRef = req.query.ref;
        if (customRef) {
            refererHeader = customRef;
        } else if (embedUrl.includes('vidsrcme.su') || embedUrl.includes('vidsrc.')) {
            refererHeader = 'https://vidsrcme.su/';
        } else if (embedUrl.includes('vidsrc-me.ru') || embedUrl.includes('vidsrcme.ru')) {
            refererHeader = 'https://vidsrcme.ru/';
        } else if (embedUrl.includes('cloudorchestranova.com/embed/movie') || embedUrl.includes('cloudorchestranova.com/embed/tv')) {
            refererHeader = 'https://vidsrcme.su/';
        } else if (embedUrl.includes('cloudorchestranova.com/embed/player')) {
            refererHeader = 'https://cloudorchestranova.com/';
        }

        const embedRes = await fetchWithTimeout(embedUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                'Referer': refererHeader,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
                'Sec-Ch-Ua': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Sec-Fetch-Dest': 'iframe',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'cross-site',
                'Upgrade-Insecure-Requests': '1'
            }
        });

        if (!embedRes.ok) {
            return res.status(embedRes.status).send(`VidSrc server trả về mã ${embedRes.status}`);
        }

        let html = await embedRes.text();
        const embedOrigin = parsed.origin;

        // Strip anti-tamper and sandbox redirect scripts that kill/blank the page
        html = html.replace(/<script[^>]*ads\.js[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*devtool-guard[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*beacon\.min\.js[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*adexchangerapid[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*canoesaisles[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*groszynudgepreter[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*glumsynemasmitham[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*histats[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*waust[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*disable-devtool[^>]*><\/script>/gi, '');
        html = html.replace(/<script[^>]*sbx\.js[^>]*><\/script>/gi, '');
        html = html.replace(/<script[^>]*>(?:(?!<\/script>)[\s\S])*?function\s+kill\(\)[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*>(?:(?!<\/script>)[\s\S])*?\/embed\/[a-f0-9]{20,}\.js[\s\S]*?<\/script>/gi, '');
        html = html.replace(/DisableDevtool/gi, 'NoDevtool');
        html = html.replace(/disable-devtool/gi, 'no-devtool');
        html = html.replace(/histats/gi, 'nohistats');
        html = html.replace(/VS_DEVTOOLS/g, 'NO_DEVTOOLS');
        html = html.replace(/VS_EXPIRED/g, 'NO_EXPIRED');

        // Injected Anti-Ad, Anti-Popup, and Resource Monitor Script
        const monitorScript = `
        <base href="${embedOrigin}/">
        <script>
        (function() {
          const originUrl = "${embedOrigin}";
          const VIDSRC_WHITELIST_PATTERN = /(?:localhost|127\\.0\\.0\\.1|vidsrcme\\.su|vidsrc\\.[a-z0-9-]+|cloudorchestranova\\.com|vidsrcme\\.ru|vidapi\\.cloud|comityofcognomen\\.site|epexegesisengine\\.site|propinquitypostulate\\.website|ataraxiaoftheapex\\.space|zenithofzircon\\.space|onomatopoeiaoverture\\.website|vercel\\.app|onrender\\.com|\\.(?:site|website|space|online|tech|store|fun|xyz|top|live|stream|cloud|pro|cc|vip|icu|cfd|sbs|bond|lat|best|mom|pw|me|tv|ws|click|link|info|biz|asia|one|today|rest|download|video|movie|run|app|is|to|io|co|club|work|world|moe|su|ru|sh|li|cx|ag|la|vc|bz|vg|ms|gs|tc|ac|im|gg|in|pm|ai|mobi|nu)|tmdb\\.org|themoviedb\\.org|opensubtitles\\.org|opensubtitles\\.com|subscene\\.com|osdb\\.link|subdl\\.com|statically\\.io|cloudfront\\.net|fastly\\.net|jwplayer\\.com|jwpcdn\\.com|cloudflare\\.com|jsdelivr\\.net)/i;
          const STREAM_TLD_REGEX = /\\.(?:site|website|space|online|tech|store|fun|xyz|top|live|stream|cloud|pro|cc|vip|icu|cfd|sbs|bond|lat|best|mom|pw|me|tv|ws|click|link|info|biz|asia|one|today|rest|download|video|movie|run|app|is|to|io|co|club|work|world|moe|su|ru|sh|li|cx|ag|la|vc|bz|vg|ms|gs|tc|ac|im|gg|in|pm|ai|mobi|nu)$/i;

          // Neutralize location.replace('about:blank') attempts
          try {
            const origLocReplace = window.location.replace;
            window.location.replace = function(u) {
              if (u === 'about:blank' || (typeof u === 'string' && u.includes('about:blank'))) {
                console.log('[VidSrc Anti-Ad] Neutralized location.replace(about:blank)');
                return;
              }
              return origLocReplace.call(window.location, u);
            };
          } catch(e) {}

          function isAllowedDomain(urlStr) {
            if (!urlStr || typeof urlStr !== 'string') return true;
            if (urlStr.startsWith('blob:') || urlStr.startsWith('data:') || urlStr.startsWith('javascript:') || urlStr.startsWith('about:')) return true;
            if (urlStr.includes('/pl/') || urlStr.includes('/content/') || urlStr.includes('page-') || urlStr.includes('.m3u8') || urlStr.includes('.ts') || urlStr.includes('.vtt') || urlStr.includes('.srt') || urlStr.includes('wasm.php') || urlStr.includes('api.php') || urlStr.includes('/embed/') || urlStr.includes('/player/') || urlStr.includes('generate.php') || urlStr.includes('rt_ping.php') || urlStr.includes('/subs/') || urlStr.includes('cache.php') || urlStr.includes('cache-vtt.php') || urlStr.includes('vs_src.php')) {
              return true;
            }
            try {
              const u = new URL(urlStr, window.location.href);
              const h = u.hostname.toLowerCase();
              if (STREAM_TLD_REGEX.test(h)) {
                return true;
              }
              return VIDSRC_WHITELIST_PATTERN.test(u.hostname);
            } catch(e) {
              return true;
            }
          }

          window.DisableDevtool = function() {};
          window.NoDevtool = function() {};
          window.devtoolsDetector = { launch: function() {}, addListener: function() {}, isPlugin: false };

          // Intercept HTMLIFrameElement src & setAttribute to proxy inner embed frames
          function resolveEmbedProxyUrl(rawUrl) {
            if (!rawUrl || typeof rawUrl !== 'string') return rawUrl;
            if (rawUrl.includes('/api/vidsrc/embed-proxy')) return rawUrl;
            if (rawUrl.startsWith('blob:') || rawUrl.startsWith('data:') || rawUrl.startsWith('javascript:')) return rawUrl;

            let absUrl = rawUrl;
            if (rawUrl.startsWith('//')) absUrl = 'https:' + rawUrl;
            else if (rawUrl.startsWith('/')) absUrl = originUrl + rawUrl;
            else if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) absUrl = originUrl + '/' + rawUrl;

            return window.location.origin + '/api/vidsrc/embed-proxy?url=' + encodeURIComponent(absUrl) + '&ref=' + encodeURIComponent(originUrl);
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

          // Suppress VS_DEVTOOLS and VS_EXPIRED postMessages from inner frames to prevent blanking the page
          const rawAddEventListener = window.addEventListener;
          window.addEventListener = function(type, listener, options) {
            if (type === 'message' && typeof listener === 'function') {
              const safeListener = function(e) {
                if (e && e.data) {
                  if (e.data.type === 'VS_DEVTOOLS' || e.data.type === 'NO_DEVTOOLS' || e.data.type === 'VS_EXPIRED') {
                    console.log('[VidSrc Anti-Ad] Neutralized session cancellation message:', e.data.type);
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
            if (rawUrl.startsWith('blob:') || rawUrl.startsWith('data:') || rawUrl.startsWith('javascript:')) return rawUrl;

            let absUrl = rawUrl;
            if (rawUrl.startsWith('//')) absUrl = 'https:' + rawUrl;
            else if (rawUrl.startsWith('/')) absUrl = originUrl + rawUrl;
            else if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) absUrl = originUrl + '/' + rawUrl;

            // Whitelist Check: Block any domain NOT in the Whitelist!
            if (!isAllowedDomain(absUrl)) {
              console.log('[Anti-Adblock VidSrc] Whitelist blocked ad resource:', absUrl);
              return 'data:text/javascript,/*blocked_by_whitelist*/';
            }

            if (absUrl.includes('jwplayer.com') || absUrl.includes('jwpcdn.com') || absUrl.includes('cloudflare.com') || absUrl.includes('jsdelivr.net')) return absUrl;

            // Intercept local relative M3U8 requests like http://localhost:3001/pl/...
            if (absUrl.includes(window.location.host) && absUrl.includes('/pl/')) {
              const realPath = absUrl.substring(absUrl.indexOf('/pl/'));
              const realTarget = 'https://comityofcognomen.site' + realPath;
              return window.location.origin + '/api/vidsrc/proxy?url=' + encodeURIComponent(realTarget) + '&ref=https%3A%2F%2Fcloudorchestranova.com';
            }

            if (absUrl.startsWith('http://') || absUrl.startsWith('https://')) {
              return window.location.origin + '/api/vidsrc/proxy?url=' + encodeURIComponent(absUrl) + '&ref=' + encodeURIComponent(originUrl);
            }
            return absUrl;
          }

          // Anti-Popup: Block window.open and return dummy window object
          window.open = function(url, target, features) {
            console.log('[Anti-Popup VidSrc] Blocked window.open attempt:', url);
            return { focus: function() {}, blur: function() {}, close: function() {}, postMessage: function() {} };
          };

          // Intercept dynamic link clicks and fake ad anchors
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

          // Global click capture to neutralize ad overlays
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

              try {
                let res;
                if (typeof input === 'string') {
                  res = await rawFetch.call(this, proxyTarget, init);
                } else if (input && typeof input === 'object' && input.url) {
                  try {
                    const newReq = new Request(proxyTarget, input);
                    res = await rawFetch.call(this, newReq, init);
                  } catch(e) {
                    res = await rawFetch.call(this, proxyTarget, init || input);
                  }
                } else {
                  res = await rawFetch.call(this, proxyTarget, init);
                }
                return res;
              } catch(err) {
                throw err;
              }
            };
          }

          if (window.XMLHttpRequest) {
            const rawOpen = window.XMLHttpRequest.prototype.open;
            const rawSend = window.XMLHttpRequest.prototype.send;
            window.XMLHttpRequest.prototype.open = function(method, url) {
              this._origUrl = url;
              const proxyTarget = resolveProxyUrl(url);
              this._proxyUrl = proxyTarget;
              const restArgs = Array.prototype.slice.call(arguments, 2);
              return rawOpen.apply(this, [method, proxyTarget].concat(restArgs));
            };
            window.XMLHttpRequest.prototype.send = function() {
              return rawSend.apply(this, arguments);
            };
          }

          // iOS Safari native HLS: intercept video.src so M3U8 URLs go through the proxy
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
            const origVidSetAttr = HTMLMediaElement.prototype.setAttribute;
            HTMLMediaElement.prototype.setAttribute = function(name, val) {
              if (String(name).toLowerCase() === 'src' && val && typeof val === 'string' && (val.includes('.m3u8') || val.includes('/pl/'))) {
                val = resolveProxyUrl(val);
              }
              return origVidSetAttr.call(this, name, val);
            };
          } catch(e) {}

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
              setTimeout(function() {
                try {
                  if (window.JWSubs && typeof window.JWSubs.auto === 'function') {
                    window.JWSubs.auto();
                  }
                } catch(e) {}
              }, 500);
              if (_hookInterval) clearInterval(_hookInterval);
            }
          }
          var _hookInterval = setInterval(hookJWSubs, 500);
          setTimeout(function() { if (_hookInterval) clearInterval(_hookInterval); }, 10000);
        })();
        </script>
        `;

        if (html.includes('<head>')) {
            html = html.replace('<head>', `<head>${monitorScript}`);
        } else {
            html = monitorScript + html;
        }

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', '*');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        res.setHeader('Referrer-Policy', 'origin');
        res.setHeader('Content-Security-Policy', "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval' data: blob:; connect-src * data: blob:; img-src * data: blob:; style-src * 'unsafe-inline';");
        return res.send(html);
    } catch (err) {
        console.error(`[vidsrc-embed-proxy] Error:`, err);
        return res.status(500).send(err.message);
    }
};

// VidSrc Stream & Resource Proxy (HLS playlist rewriting, segment tunneling, subtitle filtering)
const proxyStream = async (req, res) => {
    const targetUrl = req.query.url;
    const customRef = req.query.ref;

    if (!targetUrl) {
        return res.status(400).send('Missing url parameter');
    }

    try {
        const parsed = new URL(targetUrl);
        const hostLower = parsed.hostname.toLowerCase();
        const isStreamDomain = STREAM_TLD_REGEX.test(hostLower);

        const isStreamResource = targetUrl.includes('/pl/') || targetUrl.includes('/content/') || targetUrl.includes('page-') || targetUrl.includes('.m3u8') || targetUrl.includes('.ts') || targetUrl.includes('.vtt') || targetUrl.includes('.srt') || targetUrl.includes('wasm.php') || targetUrl.includes('api.php') || targetUrl.includes('/embed/') || targetUrl.includes('/player/') || targetUrl.includes('generate.php') || targetUrl.includes('rt_ping.php') || targetUrl.includes('/subs/') || targetUrl.includes('cache.php') || targetUrl.includes('cache-vtt.php') || targetUrl.includes('vs_src.php') || isStreamDomain;

        if (!isStreamResource && !VIDSRC_WHITELIST_PATTERN.test(parsed.hostname)) {
            console.log(`[vidsrc-proxy] Whitelist blocked ad domain: ${parsed.hostname}`);
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

        const passHeaders = {
            'User-Agent': targetUrl.includes('opensubtitles')
                ? 'TemporaryUserAgent'
                : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
        };

        if (targetUrl.includes('opensubtitles')) {
            passHeaders['X-User-Agent'] = req.headers['x-user-agent'] || 'trailers.to-UA';
        } else {
            passHeaders['Referer'] = refUrl;
            passHeaders['Origin'] = originUrlStr;
            passHeaders['Sec-Ch-Ua'] = '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"';
            passHeaders['Sec-Ch-Ua-Mobile'] = '?0';
            passHeaders['Sec-Ch-Ua-Platform'] = '"Windows"';
        }

        if (req.headers['content-type']) {
            passHeaders['Content-Type'] = req.headers['content-type'];
        }

        if (req.headers['range']) {
            passHeaders['Range'] = req.headers['range'];
        }

        const fetchOpts = {
            method: req.method,
            headers: passHeaders,
        };

        if (req.method && req.method !== 'GET' && req.method !== 'HEAD') {
            let bodyBuffer = null;
            if (Buffer.isBuffer(req.body)) {
                bodyBuffer = req.body;
            } else if (typeof req.body === 'string') {
                bodyBuffer = Buffer.from(req.body);
            } else if (typeof req.body === 'object' && req.body !== null && Object.keys(req.body).length > 0) {
                bodyBuffer = Buffer.from(JSON.stringify(req.body));
            }

            if (bodyBuffer && bodyBuffer.length > 0) {
                fetchOpts.body = bodyBuffer;
            }
        }

        const proxyRes = await fetchWithTimeout(targetUrl, fetchOpts);

        if (!proxyRes.ok && proxyRes.status !== 206) {
            return res.status(proxyRes.status).send(`VidSrc proxy trả về mã ${proxyRes.status}`);
        }

        let contentType = proxyRes.headers.get('content-type') || 'application/octet-stream';
        if (targetUrl.includes('opensubtitles')) {
            contentType = 'application/json; charset=utf-8';
        }
        let dataBuf = Buffer.from(await proxyRes.arrayBuffer());
        const textContent = dataBuf.toString('utf-8');

        // Patch subtitles.js on-the-fly to filter unsupported .ass/.sub formats and auto-retry next result on error
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

        // M3U8 Playlist Rewriter for VidSrc Stream Proxy
        if (textContent.includes('#EXTM3U')) {
            const rawProto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').toString();
            const host = req.headers.host || 'localhost:3001';
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

        res.setHeader('Content-Type', contentType.includes('mpegurl') || textContent.includes('#EXTM3U') ? 'application/vnd.apple.mpegurl' : contentType);
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Cache-Control', 'no-store');
        return res.send(dataBuf);
    } catch (err) {
        console.error(`[vidsrc-proxy] Error:`, err);
        return res.status(500).send(err.message);
    }
};

module.exports = {
    getActiveDomain,
    embedProxy,
    proxyStream
};
