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
        console.error('Error reading active vidsrc domain:', error);
        return res.json({ ok: true, active_domain: 'https://vidsrcme.su' });
    }
};

const VIDSRC_WHITELIST_PATTERN = /(?:localhost|127\.0\.0\.1|vidsrcme\.su|vidsrc\.[a-z0-9-]+|cloudorchestranova\.com|vidsrcme\.ru|vidapi\.cloud|comityofcognomen\.site|epexegesisengine\.site|propinquitypostulate\.website|ataraxiaoftheapex\.space|zenithofzircon\.space|onomatopoeiaoverture\.website|vercel\.app|onrender\.com|\.(?:site|website|space|online|tech|store|fun|xyz|top|live|stream|cloud|pro|cc|vip|icu|cfd|sbs|bond|lat|best|mom|pw|me|tv|ws|click|link|info|biz|asia|one|today|rest|download|video|movie|run|app|is|to|io|co|club|work|world|moe|su|ru|sh|li|cx|ag|la|vc|bz|vg|ms|gs|tc|ac|im|gg|in|pm|ai|mobi|nu)|tmdb\.org|themoviedb\.org|opensubtitles\.org|opensubtitles\.com|subscene\.com|osdb\.link|subdl\.com|statically\.io|cloudfront\.net|fastly\.net|jwplayer\.com|jwpcdn\.com|cloudflare\.com|jsdelivr\.net)/i;
const STREAM_TLD_REGEX = /\.(?:site|website|space|online|tech|store|fun|xyz|top|live|stream|cloud|pro|cc|vip|icu|cfd|sbs|bond|lat|best|mom|pw|me|tv|ws|click|link|info|biz|asia|one|today|rest|download|video|movie|run|app|is|to|io|co|club|work|world|moe|su|ru|sh|li|cx|ag|la|vc|bz|vg|ms|gs|tc|ac|im|gg|in|pm|ai|mobi|nu)$/i;

// VidSrc Embed Proxy (Ad-blocking, Whitelist, Referer Bypassing)
const embedProxy = async (req, res) => {
    const embedUrl = req.query.url;
    if (!embedUrl) {
        return res.status(400).send('Missing url parameter');
    }

    if (embedUrl.includes('about:blank') || embedUrl.startsWith('about:')) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Access-Control-Allow-Origin', '*');
        return res.send('<html><body></body></html>');
    }

    try {
        let targetEmbedUrl = embedUrl;
        if (targetEmbedUrl.includes('/embed/movie') || targetEmbedUrl.includes('/embed/tv')) {
            targetEmbedUrl = targetEmbedUrl.replace(/https?:\/\/(?:vidsrc\.[a-z0-9-]+|vidsrcme\.su|vidsrcme\.ru)/i, 'https://vidsrcme.su');
        }
        // Clean ds_lang parameter if it contains encoded comma (%2C or ,) to avoid Cloudflare 403 Forbidden WAF blocks
        if (targetEmbedUrl.includes('ds_lang=')) {
            targetEmbedUrl = targetEmbedUrl.replace(/ds_lang=([^&]+)/gi, (m, langVal) => {
                const cleanLang = decodeURIComponent(langVal).split(',')[0].trim();
                return `ds_lang=${cleanLang}`;
            });
        }

        const parsed = new URL(targetEmbedUrl);

        const customRef = req.query.ref;
        let refererHeader = customRef ? (customRef.endsWith('/') ? customRef : customRef + '/') : `${parsed.origin}/`;
        if (customRef) {
            refererHeader = customRef.endsWith('/') ? customRef : customRef + '/';
        } else if (targetEmbedUrl.includes('cloudorchestranova.com/embed/movie') || targetEmbedUrl.includes('cloudorchestranova.com/embed/tv')) {
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
            timeout: 15000,
            responseType: 'text'
        });

        console.log(`[vidsrc-embed-proxy] ✅ Response (200 OK) for: ${targetEmbedUrl}`);
        let html = embedRes.data;

        // Clean known ad scripts & devtool killers safely
        html = html.replace(/<script[^>]*ads\.js[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*devtool-guard[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*disable-devtool[^>]*><\/script>/gi, '');
        html = html.replace(/<script[^>]*no-devtool[^>]*><\/script>/gi, '');
        html = html.replace(/<script[^>]*beacon\.min\.js[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*adexchangerapid[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*canoesaisles[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*groszynudgepreter[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*glumsynemasmitham[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*histats[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*waust[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*sbx\.js[^>]*><\/script>/gi, '');
        html = html.replace(/<script[^>]*>(?:(?!<\/script>)[\s\S])*?function\s+kill\(\)[\s\S]*?<\/script>/gi, '');
        html = html.replace(/<script[^>]*>(?:(?!<\/script>)[\s\S])*?\/embed\/[a-f0-9]{20,}\.js[\s\S]*?<\/script>/gi, '');
        html = html.replace(/location\.replace\(['"]about:blank['"]\)/gi, 'console.log("[Anti-Devtools] Bypassed about:blank")');
        html = html.replace(/document\.documentElement\.innerHTML\s*=\s*['"]['"]/gi, 'console.log("[Anti-Devtools] Bypassed innerHTML clear")');
        html = html.replace(/DisableDevtool/gi, 'NoDevtool');
        html = html.replace(/disable-devtool/gi, 'no-devtool');
        html = html.replace(/histats/gi, 'nohistats');
        html = html.replace(/VS_DEVTOOLS/g, 'NO_DEVTOOLS');
        html = html.replace(/VS_EXPIRED/g, 'NO_EXPIRED');

        const embedOrigin = parsed.origin;
        const rawProto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').toString();
        const host = req.get('host') || req.headers.host || 'localhost:3001';
        const protocol = (rawProto.includes('https') || host.includes('onrender.com')) ? 'https' : 'http';
        const serverOrigin = `${protocol}://${host}`;

        const monitorScript = `
        <base href="${embedOrigin}/">
        <script>
        (function() {
          const originUrl = "${embedOrigin}";
          const localServerOrigin = "${serverOrigin}";
          const VIDSRC_WHITELIST_PATTERN = /(?:localhost|127\\.0\\.0\\.1|vidsrcme\\.su|vidsrc\\.[a-z0-9-]+|cloudorchestranova\\.com|vidsrcme\\.ru|vidapi\\.cloud|comityofcognomen\\.site|epexegesisengine\\.site|propinquitypostulate\\.website|ataraxiaoftheapex\\.space|zenithofzircon\\.space|onomatopoeiaoverture\\.website|vercel\\.app|onrender\\.com|\\.(?:site|website|space|online|tech|store|fun|xyz|top|live|stream|cloud|pro|cc|vip|icu|cfd|sbs|bond|lat|best|mom|pw|me|tv|ws|click|link|info|biz|asia|one|today|rest|download|video|movie|run|app|is|to|io|co|club|work|world|moe|su|ru|sh|li|cx|ag|la|vc|bz|vg|ms|gs|tc|ac|im|gg|in|pm|ai|mobi|nu)|tmdb\\.org|themoviedb\\.org|opensubtitles\\.org|opensubtitles\\.com|subscene\\.com|osdb\\.link|subdl\\.com|statically\\.io|cloudfront\\.net|fastly\\.net|jwplayer\\.com|jwpcdn\\.com|cloudflare\\.com|jsdelivr\\.net)/i;
          const STREAM_TLD_REGEX = /\\.(?:site|website|space|online|tech|store|fun|xyz|top|live|stream|cloud|pro|cc|vip|icu|cfd|sbs|bond|lat|best|mom|pw|me|tv|ws|click|link|info|biz|asia|one|today|rest|download|video|movie|run|app|is|to|io|co|club|work|world|moe|su|ru|sh|li|cx|ag|la|vc|bz|vg|ms|gs|tc|ac|im|gg|in|pm|ai|mobi|nu)$/i;

          console.log('[VidSrc Anti-Ad] 🛡️ Anti-ad & anti-redirect shield initialized');
          console.log('[VidSrc Subtitle] 🚀 Subtitle subsystem initialized (OpenSubtitles Direct + VTT Proxy)');

          // Neutralize location.replace('about:blank') attempts
          try {
            const origLocReplace = window.location.replace;
            window.location.replace = function(u) {
              if (u === 'about:blank' || (typeof u === 'string' && u.includes('about:blank'))) {
                console.warn('[VidSrc Anti-Ad] 🛡️ Neutralized location.replace("about:blank") ad-trap');
                return;
              }
              return origLocReplace.call(window.location, u);
            };
          } catch(e) {}

          window.DisableDevtool = function() {};
          window.NoDevtool = function() {};
          window.devtoolsDetector = { launch: function() {}, addListener: function() {}, isPlugin: false };

          try {
            for (var k in localStorage) {
              if (k && k.indexOf('va_subtitle_') === 0) localStorage.removeItem(k);
            }
          } catch(e) {}

          function isAllowedDomain(urlStr) {
            if (!urlStr || typeof urlStr !== 'string') return true;
            if (urlStr.startsWith('blob:') || urlStr.startsWith('data:') || urlStr.startsWith('javascript:') || urlStr.startsWith('about:')) return true;
            const lower = urlStr.toLowerCase();
            if (lower.includes('/pl/') || lower.includes('/content/') || lower.includes('page-') || lower.includes('.m3u8') || lower.includes('.ts') || lower.includes('.vtt') || lower.includes('.srt') || lower.includes('.gz') || lower.includes('.key') || lower.includes('.wasm') || lower.includes('.woff') || lower.includes('.woff2') || lower.includes('.ttf') || lower.includes('.js') || lower.includes('.css') || lower.includes('.json') || lower.includes('wasm.php') || lower.includes('api.php') || lower.includes('cache.php') || lower.includes('cache-vtt.php') || lower.includes('.php') || lower.includes('/embed/') || lower.includes('/player/') || lower.includes('/src/') || lower.includes('vs_src.php') || lower.includes('generate.php') || lower.includes('rt_ping.php') || lower.includes('/subs/')) {
              return true;
            }
            try {
              const u = new URL(urlStr, window.location.href);
              const h = u.hostname.toLowerCase();
              if (STREAM_TLD_REGEX.test(h)) {
                return true;
              }
              const allowed = VIDSRC_WHITELIST_PATTERN.test(u.hostname);
              if (!allowed) {
                console.warn('[VidSrc Anti-Ad] 🚫 Whitelist rejected ad/tracking domain:', h, 'URL:', urlStr);
              }
              return allowed;
            } catch(e) {
              return true;
            }
          }

          function resolveEmbedProxyUrl(rawUrl) {
            if (!rawUrl || typeof rawUrl !== 'string') return rawUrl;
            if (rawUrl.startsWith('about:') || rawUrl.includes('about:blank')) return rawUrl;
            if (rawUrl.includes('/api/vidsrc/embed-proxy')) return rawUrl;
            if (rawUrl.startsWith('blob:') || rawUrl.startsWith('data:') || rawUrl.startsWith('javascript:')) return rawUrl;

            let absUrl = rawUrl;
            if (rawUrl.startsWith('//')) absUrl = 'https:' + rawUrl;
            else if (rawUrl.startsWith('/')) absUrl = originUrl + rawUrl;
            else if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) absUrl = originUrl + '/' + rawUrl;

            const baseOrigin = window.location.origin || localServerOrigin;
            const finalEmbed = baseOrigin + '/api/vidsrc/embed-proxy?url=' + encodeURIComponent(absUrl) + '&ref=' + encodeURIComponent(originUrl);
            console.log('[VidSrc Anti-Ad] 🔄 Proxied inner iframe cleanly:', absUrl, '->', finalEmbed);
            return finalEmbed;
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
                  if (e.data.type === 'VS_DEVTOOLS' || e.data.type === 'NO_DEVTOOLS' || e.data.type === 'VS_EXPIRED') {
                    console.warn('[VidSrc Anti-Ad] 🛡️ Neutralized session cancellation message:', e.data.type);
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
              console.warn('[VidSrc Anti-Ad] 🚫 Whitelist blocked ad resource:', absUrl);
              return 'data:text/javascript,/*blocked_by_whitelist*/';
            }

            if (absUrl.includes('jwplayer.com') || absUrl.includes('jwpcdn.com') || absUrl.includes('cloudflare.com') || absUrl.includes('jsdelivr.net')) return absUrl;

            // CRITICAL: Let OpenSubtitles requests bypass the proxy and go direct from browser.
            // Data Center IPs (Render/AWS/Vercel) get 403-blocked by OpenSubtitles WAF,
            // but residential browser IPs work fine. OpenSubtitles has CORS (Access-Control-Allow-Origin: *)
            // so browser can call directly without proxy.
            if (absUrl.includes('opensubtitles.org') || absUrl.includes('opensubtitles.com')) {
              console.log('[VidSrc Subtitle] 🚀 Direct browser call to OpenSubtitles (bypassing server proxy):', absUrl);
              return absUrl;
            }

            const baseOrigin = window.location.origin || localServerOrigin;

            // Intercept local relative M3U8 requests like http://localhost:3001/pl/...
            if (absUrl.includes(window.location.host) && absUrl.includes('/pl/')) {
              const realPath = absUrl.substring(absUrl.indexOf('/pl/'));
              const realTarget = 'https://comityofcognomen.site' + realPath;
              console.log('[VidSrc Stream] 🎥 Intercepted local /pl/ request ->', realTarget);
              return baseOrigin + '/api/vidsrc/proxy?url=' + encodeURIComponent(realTarget) + '&ref=https%3A%2F%2Fcloudorchestranova.com';
            }

            // Route relative server calls (like /cache-vtt.php, /get_sub_url) to originUrl via proxy
            if (absUrl.includes(window.location.host) && !absUrl.includes('/api/vidsrc/')) {
              try {
                const u = new URL(absUrl);
                const realTarget = originUrl + u.pathname + u.search;
                console.log('[VidSrc Subtitle] 🔀 Local-relative subtitle endpoint rerouted to origin via proxy:', absUrl, '->', realTarget);
                return baseOrigin + '/api/vidsrc/proxy?url=' + encodeURIComponent(realTarget) + '&ref=' + encodeURIComponent(originUrl);
              } catch(e) {}
            }

            if (absUrl.startsWith('http://') || absUrl.startsWith('https://')) {
              if (absUrl.includes('/get_sub_url') || absUrl.includes('cache-vtt') || absUrl.includes('subtitles.js') || absUrl.includes('.vtt') || absUrl.includes('.srt') || absUrl.includes('.ass')) {
                console.log('[VidSrc Subtitle] 🔀 Subtitle asset proxied via server:', absUrl);
              }
              return baseOrigin + '/api/vidsrc/proxy?url=' + encodeURIComponent(absUrl) + '&ref=' + encodeURIComponent(originUrl);
            }
            return absUrl;
          }

          window.open = function(url, target, features) {
            console.warn('[VidSrc Anti-Ad] 🚫 Blocked popup window.open attempt:', url, 'target:', target);
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
                    console.warn('[VidSrc Anti-Ad] 🚫 Blocked fake link click:', el.href);
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
                  console.warn('[VidSrc Anti-Ad] 🚫 Intercepted click ad navigation:', el.href);
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
              if (url.includes('opensubtitles') || url.includes('subtitles') || url.includes('/get_sub_url') || url.includes('.vtt')) {
                console.log('[VidSrc Subtitle] 🌐 fetch() intercepted:', url, '->', proxyTarget);
              }

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
            const rawSend = window.XMLHttpRequest.prototype.send;
            window.XMLHttpRequest.prototype.open = function(method, url) {
              this._origUrl = url;
              const proxyTarget = resolveProxyUrl(url);
              this._proxyUrl = proxyTarget;
              if (url.includes('opensubtitles') || url.includes('subtitles') || url.includes('/get_sub_url') || url.includes('.vtt') || url.includes('.srt')) {
                console.log('[VidSrc Subtitle] 🌐 XHR open(' + method + ') intercepted:', url, '->', proxyTarget);
              }
              const restArgs = Array.prototype.slice.call(arguments, 2);
              return rawOpen.apply(this, [method, proxyTarget].concat(restArgs));
            };
            window.XMLHttpRequest.prototype.send = function() {
              return rawSend.apply(this, arguments);
            };
          }

          // Hook HTMLTrackElement so subtitle tracks (.vtt/.srt) route through proxy with proper CORS
          try {
            const origTrackSrcDesc = Object.getOwnPropertyDescriptor(HTMLTrackElement.prototype, 'src');
            if (origTrackSrcDesc && origTrackSrcDesc.set) {
              Object.defineProperty(HTMLTrackElement.prototype, 'src', {
                get: origTrackSrcDesc.get,
                set: function(val) {
                  console.log('[VidSrc Subtitle] 🎬 Setting <track src>:', val);
                  const proxied = resolveProxyUrl(val);
                  if (proxied !== val) {
                    console.log('[VidSrc Subtitle] 🔀 Proxied <track src> to:', proxied);
                  }
                  this.addEventListener('load', function() {
                    console.log('[VidSrc Subtitle] 🎯 Subtitle track loaded successfully on <video> element!');
                  }, { once: true });
                  this.addEventListener('error', function(err) {
                    console.error('[VidSrc Subtitle] ❌ Subtitle track failed to load on <video> element:', err);
                  }, { once: true });
                  return origTrackSrcDesc.set.call(this, proxied);
                },
                configurable: true
              });
            }
            const origTrackSetAttr = HTMLTrackElement.prototype.setAttribute;
            HTMLTrackElement.prototype.setAttribute = function(name, val) {
              if (String(name).toLowerCase() === 'src') {
                console.log('[VidSrc Subtitle] 🎬 setAttribute("src") on <track>:', val);
                val = resolveProxyUrl(val);
              }
              return origTrackSetAttr.call(this, name, val);
            };
          } catch(e) {}

          // iOS Safari native HLS: intercept video.src so M3U8 URLs go through the proxy
          try {
            const vidSrcDesc = Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'src')
                            || Object.getOwnPropertyDescriptor(HTMLVideoElement.prototype, 'src');
            if (vidSrcDesc && vidSrcDesc.set) {
              Object.defineProperty(HTMLMediaElement.prototype, 'src', {
                get: vidSrcDesc.get,
                set: function(val) {
                  if (val && typeof val === 'string' && (val.includes('.m3u8') || val.includes('/pl/'))) {
                    console.log('[VidSrc Player] 🎬 Setting <video src>:', val);
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
                console.log('[VidSrc Player] 🎬 setAttribute("src") on video:', val);
                val = resolveProxyUrl(val);
              }
              return origVidSetAttr.call(this, name, val);
            };
          } catch(e) {}

          // Auto-trigger subtitle loading: Hook into JWSubs.setup so
          // auto() runs immediately after player receives IMDB ID from API
          var _hookedSetup = false;
          function hookJWSubs() {
            if (window.JWSubs && window.JWSubs.setup && !_hookedSetup) {
              _hookedSetup = true;
              console.log('[VidSrc Subtitle] 📡 JWSubs module detected, attaching setup hook...');
              var origSetup = window.JWSubs.setup;
              window.JWSubs.setup = function(data) {
                console.log('[VidSrc Subtitle] 📋 JWSubs.setup called with payload:', data);
                if (data && window.SUB) {
                  if (data.imdb_id) window.SUB.imdbId = String(data.imdb_id).replace(/^tt/i, '');
                  if (data.season) window.SUB.season = parseInt(data.season, 10);
                  if (data.episode) window.SUB.episode = parseInt(data.episode, 10);
                  console.log('[VidSrc Subtitle] 📋 window.SUB configured:', { imdbId: window.SUB.imdbId, season: window.SUB.season, episode: window.SUB.episode });
                }
                var res = origSetup.apply(this, arguments);
                if (data && window.SUB) {
                  if (data.imdb_id) window.SUB.imdbId = String(data.imdb_id).replace(/^tt/i, '');
                  if (data.season) window.SUB.season = parseInt(data.season, 10);
                  if (data.episode) window.SUB.episode = parseInt(data.episode, 10);
                }
                setTimeout(function() {
                  try {
                    if (window.JWSubs && typeof window.JWSubs.auto === 'function') {
                      console.log('[VidSrc Subtitle] ⏳ Triggering JWSubs.auto()...');
                      window.JWSubs.auto();
                    }
                  } catch(e) {
                    console.error('[VidSrc Subtitle] ❌ Error in JWSubs.auto():', e);
                  }
                }, 300);
                return res;
              };
            }
            if (window.JWSubs && typeof window.JWSubs.auto === 'function') {
              try {
                console.log('[VidSrc Subtitle] ⏳ Triggering JWSubs.auto() (interval check)...');
                window.JWSubs.auto();
              } catch(e) {}
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

function assToVtt(assText) {
    const lines = assText.split(/\r?\n/);
    const vttLines = ['WEBVTT\n'];
    for (let line of lines) {
        if (line.startsWith('Dialogue:')) {
            const parts = line.substring(9).split(',');
            if (parts.length >= 10) {
                const start = parts[1].trim();
                const end = parts[2].trim();
                let text = parts.slice(9).join(',').trim();
                text = text.replace(/\{[^}]+\}/g, '').replace(/\\N/gi, '\n');
                const fmtTime = (t) => {
                    const match = t.match(/(\d+):(\d{2}):(\d{2})[.,](\d{2,3})/);
                    if (!match) return t;
                    const h = match[1].padStart(2, '0');
                    const m = match[2];
                    const s = match[3];
                    const ms = match[4].padEnd(3, '0');
                    return `${h}:${m}:${s}.${ms}`;
                };
                const vttStart = fmtTime(start);
                const vttEnd = fmtTime(end);
                if (text) {
                    vttLines.push(`${vttStart} --> ${vttEnd}\n${text}\n`);
                }
            }
        }
    }
    return vttLines.join('\n');
}

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
            const cachedTxt = Buffer.from(cached.data).toString('utf-8').trim();
            if (cachedTxt === '[]' || cachedTxt.length <= 2 || cachedTxt.includes('403 Forbidden') || cachedTxt.includes('Just a moment')) {
                subSearchCache.delete(targetUrl);
            } else {
                res.setHeader('Content-Type', cached.contentType);
                res.setHeader('Access-Control-Allow-Origin', '*');
                res.setHeader('Cache-Control', 'public, max-age=21600');
                return res.send(cached.data);
            }
        }
    }

    try {
        const parsed = new URL(targetUrl);
        const lowerUrl = targetUrl.toLowerCase();
        const lowerHost = parsed.hostname.toLowerCase();

        const isStreamResource = lowerUrl.includes('/pl/') || 
                                 lowerUrl.includes('/content/') || 
                                 lowerUrl.includes('page-') || 
                                 lowerUrl.includes('.m3u8') || 
                                 lowerUrl.includes('.ts') || 
                                 lowerUrl.includes('.vtt') || 
                                 lowerUrl.includes('.srt') || 
                                 lowerUrl.includes('.ass') || 
                                 lowerUrl.includes('.ssa') || 
                                 lowerUrl.includes('.gz') || 
                                 lowerUrl.includes('/subtitles/') || 
                                 lowerUrl.includes('/sub/') || 
                                 lowerUrl.includes('/subs/') || 
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
                                 lowerUrl.includes('cache.php') || 
                                 lowerUrl.includes('cache-vtt.php') || 
                                 lowerUrl.includes('.php') || 
                                 lowerUrl.includes('/embed/') || 
                                 lowerUrl.includes('/player/') || 
                                 lowerUrl.includes('/src/') || 
                                 lowerUrl.includes('vs_src.php') || 
                                 lowerUrl.includes('generate.php') || 
                                 lowerUrl.includes('rt_ping.php') || 
                                 STREAM_TLD_REGEX.test(lowerHost);

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

        if (targetUrl.includes('opensubtitles')) {
            console.log(`[vidsrc-proxy] 🔀 Subtitle: OpenSubtitles request -> ${targetUrl}`);
        } else if (targetUrl.includes('subtitles.js')) {
            console.log(`[vidsrc-proxy] 🔀 Subtitle: subtitles.js requested, applying on-the-fly patches...`);
        } else if (targetUrl.includes('/get_sub_url')) {
            console.log(`[vidsrc-proxy] 🔄 Subtitle: /get_sub_url conversion request (method: ${req.method})`);
        } else if (targetUrl.includes('cache-vtt') || targetUrl.includes('.vtt') || targetUrl.includes('.srt') || targetUrl.includes('.ass')) {
            console.log(`[vidsrc-proxy] 📄 Subtitle: fetching subtitle file -> ${targetUrl}`);
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

            if (bodyBuffer && bodyBuffer.length > 0) {
                axiosConfig.data = bodyBuffer;
            }
        }

        let proxyRes = null;

        if (targetUrl.includes('opensubtitles')) {
            const osUAs = [
                'TemporaryUserAgent',
                'VLSub 0.10.2',
                'OpenSubtitlesPlayer v4.7',
                'trailers.to-UA',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
            ];

            for (const ua of osUAs) {
                const cleanHeaders = {
                    'User-Agent': ua,
                    'X-User-Agent': ua,
                    'Accept': '*/*',
                    'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8'
                };
                const cfg = {
                    method: req.method || 'GET',
                    url: targetUrl,
                    headers: cleanHeaders,
                    responseType: 'arraybuffer',
                    timeout: 10000,
                    validateStatus: () => true
                };
                try {
                    const r = await axios(cfg);
                    if (r.status === 200 && r.data && r.data.length > 2) {
                        const txt = Buffer.from(r.data).toString('utf-8');
                        if (!txt.includes('Just a moment') && !txt.includes('403 Forbidden')) {
                            console.log(`[vidsrc-proxy] ✅ OpenSubtitles success with UA: ${ua}`);
                            proxyRes = r;
                            break;
                        }
                    }
                } catch(e) {}
            }
        }

        if (!proxyRes) {
            proxyRes = await axios(axiosConfig);
        }

        let contentType = proxyRes.headers['content-type'] || 'application/octet-stream';
        if (targetUrl.includes('opensubtitles') && contentType.includes('text/html')) {
            contentType = 'application/json; charset=utf-8';
        }

        let dataBuf = Buffer.from(proxyRes.data);
        let textContent = dataBuf.toString('utf-8').replace(/^\uFEFF/, '').replace(/^\xEF\xBB\xBF/, '');

        // Convert .ass/.ssa subtitles to WebVTT format on-the-fly
        if (targetUrl.includes('.ass') || targetUrl.includes('.ssa') || textContent.startsWith('[Script Info]') || (textContent.includes('ScriptType:') && textContent.includes('Dialogue:'))) {
            const convertedVtt = assToVtt(textContent);
            dataBuf = Buffer.from(convertedVtt, 'utf-8');
            contentType = 'text/vtt; charset=utf-8';
        }

        // Patch subtitles.js on-the-fly to filter unsupported binary formats, add logging, and ensure robust subtitle loading
        if (targetUrl.includes('subtitles.js')) {
            console.log(`[vidsrc-proxy] 🔀 Serving and patching subtitles.js for: ${targetUrl}`);
            let jsText = textContent;
            
            // 1. Log when OpenSubtitles search is initiated
            jsText = jsText.replace(
                "login(callback , imdb, lang_ids = [\"all\"], s = 0, e = 0) {",
                `login(callback , imdb, lang_ids = ["all"], s = 0, e = 0) {
        console.log('[VidSrc Subtitle] 🔍 OpenSubtitles search initiated for IMDB:', $("body").data("i"), 'Season:', $("body").data("s"), 'Episode:', $("body").data("e"));`
            );
            
            // 2. Log when OpenSubtitles response is received
            jsText = jsText.replace(
                "showOpsLangs();",
                `console.log('[VidSrc Subtitle] 📥 OpenSubtitles response received:', (data && data.length) ? (data.length + ' subtitles found') : '0 subtitles', 'Languages available:', Object.keys(ops_subs));
                showOpsLangs();`
            );

            // 3. Log when user views subtitle list for a specific language
            jsText = jsText.replace(
                "function showOpsSubs(subkey){",
                `function showOpsSubs(subkey){
    console.log('[VidSrc Subtitle] 📋 Subtitle items displayed for language:', subkey, ops_subs[subkey]);`
            );

            // 4. Log when user clicks a subtitle to download
            jsText = jsText.replace(
                "$(document).on('click', \".subtitles .subtitle\", function() {",
                `$(document).on('click', ".subtitles .subtitle", function() {
        console.log('[VidSrc Subtitle] 🖱️ User selected subtitle:', $(this).data("lang"), '(' + $(this).data("subformat") + ') ID:', $(this).data("id"), 'Download URL:', $(this).data("url"));
        console.log('[VidSrc Subtitle] ⬇️ Downloading subtitle (.gz) via XHR...');`
            );

            // 5. Log when .gz is downloaded
            jsText = jsText.replace(
                "if (xhr.status === 200){",
                `if (xhr.status === 200){
                console.log('[VidSrc Subtitle] 📦 Subtitle file (.gz) downloaded successfully (size: ' + (xhr.response ? xhr.response.byteLength : 0) + ' bytes)');
                console.log('[VidSrc Subtitle] 🔄 Sending .gz to /get_sub_url for VTT conversion...');`
            );

            // 6. Log when /get_sub_url finishes conversion
            jsText = jsText.replace(
                "sub_url = data;",
                `sub_url = data;
                    console.log('[VidSrc Subtitle] ✅ /get_sub_url converted VTT URL:', data);`
            );

            // 7. Log addTextTrack
            jsText = jsText.replace(
                "function addTextTrack(sub_data , is_default = true){",
                `function addTextTrack(sub_data , is_default = true){
    console.log('[VidSrc Subtitle] 🎬 addTextTrack() adding track to <video>:', sub_data);`
            );

            // 8. Log track load
            jsText = jsText.replace(
                "track.addEventListener(\"load\", function() {",
                `track.addEventListener("load", function() {
        console.log('[VidSrc Subtitle] 🎯 Subtitle track loaded and active on <video> element!');`
            );

            // Older/alternative player replacements:
            jsText = jsText.replace(
                "var imdb = CONFIG.imdb || d.imdb_id || '';",
                "var imdb = d.imdb_id || CONFIG.imdb || '';"
            ).replace(
                "SUB.season = CONFIG.season || (d.season ? parseInt(d.season, 10) : null);",
                "SUB.season = (d.season ? parseInt(d.season, 10) : null) || CONFIG.season;"
            ).replace(
                "SUB.episode = CONFIG.episode || (d.episode ? parseInt(d.episode, 10) : null);",
                "SUB.episode = (d.episode ? parseInt(d.episode, 10) : null) || CONFIG.episode;"
            ).replace(
                "searchOS(lang).then(function (data) {",
                `searchOS(lang).then(function (data) {
        console.log('[VidSrc Subtitle] 🔍 searchOS() returned:', data ? data.length + ' results' : '0');
        if (Array.isArray(data)) {
            data = data.filter(function(s) {
                var fn = (s.SubFileName || s.MovieReleaseName || s.SubFormat || '').toLowerCase();
                return !fn.endsWith('.sub') && !fn.endsWith('.idx') && s.SubFormat !== 'sub';
            });
        }`
            ).replace(
                "resolveVtt(sub).then(function (url) {",
                `resolveVtt(sub).then(function (url) {
            console.log('[VidSrc Subtitle] 🔄 resolveVtt() resolved to:', url);
            if (!url && idx + 1 < SUB.results.length) {
                console.log('[VidSrc Subtitle] ⚠️ Subtitle failed, trying next result index:', idx + 1);
                loadResult(idx + 1, silent);
                return;
            }`
            );
            dataBuf = Buffer.from(jsText, 'utf-8');
        }

        // M3U8 Playlist Rewriter for VidSrc Stream Proxy
        if (textContent.includes('#EXTM3U')) {
            const rawProto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').toString();
            const host = req.get('host') || req.headers.host || 'localhost:3001';
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
        res.setHeader('Access-Control-Allow-Headers', '*');
        res.setHeader('Accept-Ranges', 'bytes');
        res.setHeader('Cache-Control', 'no-store');

        if (targetUrl.includes('opensubtitles.org/search/') && proxyRes.status === 200) {
            try {
                const parsedArr = JSON.parse(textContent);
                if (Array.isArray(parsedArr) && parsedArr.length > 0) {
                    subSearchCache.set(targetUrl, {
                        data: dataBuf,
                        contentType: contentType,
                        time: Date.now()
                    });
                }
            } catch(e) {}
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
