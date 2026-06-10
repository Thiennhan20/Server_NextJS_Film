const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const axios = require('axios');
const brevoSdk = require('@getbrevo/brevo');

const brevoEmailApi = new brevoSdk.TransactionalEmailsApi();
brevoEmailApi.setApiKey(brevoSdk.TransactionalEmailsApiApiKeys.apiKey, process.env.BREVO_API_KEY || '');
const { optimizeAvatar } = require('../utils/avatarOptimizer');
const { RateLimiterMemory } = require('rate-limiter-flexible');

// Rate limiter: 5 requests per 10 minutes per IP
const rateLimiter = new RateLimiterMemory({
    points: 5,
    duration: 600, // 10 minutes
});

// Helper function to download and optimize external avatar
async function downloadAndOptimizeAvatar(avatarUrl) {
    try {
        if (!avatarUrl || !avatarUrl.startsWith('http')) {
            return avatarUrl;
        }

        // Download avatar
        const response = await axios.get(avatarUrl, {
            responseType: 'arraybuffer',
            timeout: 10000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        });

        // Optimize with Sharp
        const optimized = await optimizeAvatar(Buffer.from(response.data));

        return optimized; // Returns base64 WebP
    } catch {
        // Return original URL as fallback
        return avatarUrl;
    }
}

function createToken(userId, sessionId = null) {
    const payload = { userId };
    if (sessionId) {
        payload.sessionId = sessionId;
    }
    return jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: '15m' } // 15 minutes Access Token
    );
}

function parseUserAgent(uaString) {
    if (!uaString) return 'Unknown Device';

    let os = 'Unknown OS';
    if (/windows/i.test(uaString)) os = 'Windows';
    else if (/macintosh|mac os x/i.test(uaString) && !/like mac os x/i.test(uaString)) os = 'macOS';
    else if (/iphone|ipad|ipod/i.test(uaString)) os = 'iOS';
    else if (/android/i.test(uaString)) os = 'Android';
    else if (/linux/i.test(uaString)) os = 'Linux';

    let browser = 'Unknown Browser';
    if (/edg/i.test(uaString)) browser = 'Edge';
    else if (/chrome|crios/i.test(uaString)) browser = 'Chrome';
    else if (/firefox|fxios/i.test(uaString)) browser = 'Firefox';
    else if (/safari/i.test(uaString) && !/chrome|crios|android/i.test(uaString)) browser = 'Safari';
    else if (/opr/i.test(uaString)) browser = 'Opera';

    return `${browser} on ${os}`;
}

function formatUserResponse(user) {
    return {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar || '',
        originalAvatar: user.originalAvatar || '',
        authType: user.authType || 'email',
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
    };
}

function generateVerificationToken() {
    return crypto.randomBytes(32).toString('hex');
}

function buildVerifyUrl(token, email) {
    return `${process.env.CLIENT_URL || 'http://localhost:3000'}/verify-email?token=${token}&email=${encodeURIComponent(email)}`;
}

function buildVerificationEmailHtml(name, verifyUrl) {
    return `
            <div style="max-width:600px;margin:0 auto;padding:20px 10px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
              <div style="background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);border-radius:16px;padding:24px 16px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,0.2);position:relative;overflow:hidden;">
                
                <!-- Content wrapper -->
                <div style="position:relative;z-index:1;">
                  
                  <!-- Icon -->
                  <div style="width:60px;height:60px;margin:0 auto 12px;background:rgba(255,255,255,0.2);border-radius:50%;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(5px);">
                    <img src='https://cdn-icons-png.flaticon.com/512/616/616490.png' alt='Film Reel' style='width:30px;height:30px;filter:brightness(0) invert(1);'/>
                  </div>
                  
                  <!-- Heading -->
                  <h1 style="color:#ffffff;margin:0 0 12px 0;font-size:24px;font-weight:700;letter-spacing:-0.5px;">
                    Welcome <span style="color:#ffd700; text-shadow: 0 0 8px rgba(255, 215, 0, 0.8), 0 0 15px rgba(255, 215, 0, 0.6);">${name}</span>!
                  </h1>
                  
                  <!-- Description -->
                  <p style="color:rgba(255,255,255,0.95);font-size:14px;line-height:1.5;margin:0 0 20px 0;max-width:350px;margin-left:auto;margin-right:auto;">
                    Thank you for registering with Entertainment World!
                  </p>
                  <p style="color:rgba(255,255,255,0.95);font-size:14px;line-height:1.5;margin:0 0 20px 0;max-width:350px;margin-left:auto;margin-right:auto;">
                    Please click the button below to verify your email address to complete your registration and start exploring.
                  </p>

                  <!-- Arrows -->
                  <div style="margin-bottom: 20px; color: #ffffff;">
                    <span style="display: block; margin: 0 auto;">▼</span>
                    <span style="display: block; margin: 0 auto;">▼</span>
                  </div>
                  
                  <!-- Button -->
                  <a href="${verifyUrl}" style="display:inline-block;padding:12px 32px;background:#ffffff;color:#1e40af;font-weight:700;font-size:14px;border:2px solid #1e40af;border-radius:8px;text-decoration:none;box-shadow:0 6px 20px rgba(30, 64, 175, 0.4), inset 0 0 8px rgba(30, 64, 175, 0.3);transition:all 0.3s ease;letter-spacing:0.5px;">
                    Verify Email Address
                  </a>
                  
                  <!-- Divider -->
                  <div style="height:1px;background:rgba(255,255,255,0.2);margin:16px auto;max-width:60%;"></div>
                  
                  <!-- Help text -->
                  <p style="color:rgba(255,255,255,0.7);font-size:12px;margin:0;">
                    Need help? Contact us or try signing up again.
                  </p>
                  
                </div>
              </div>
              
              <!-- Footer -->
              <p style="text-align:center;color:#888;font-size:11px;margin-top:16px;line-height:1.4;">
                This email was sent by Entertainment World. If you didn't request this verification, please ignore this email.
              </p>
            </div>
          `;
}

async function sendVerificationEmail(email, name, verifyUrl, subject) {
    const sendSmtpEmail = new brevoSdk.SendSmtpEmail();
    sendSmtpEmail.to = [{ email }];
    sendSmtpEmail.sender = { email: process.env.BREVO_SENDER_EMAIL, name: process.env.BREVO_SENDER_NAME || 'Entertainment World' };
    sendSmtpEmail.subject = subject || 'Entertainment World Account Email Verification';
    sendSmtpEmail.htmlContent = buildVerificationEmailHtml(name, verifyUrl);
    await brevoEmailApi.sendTransacEmail(sendSmtpEmail);
}

function buildPasswordResetEmailHtml(name, resetUrl) {
    return `
      <!DOCTYPE html>
      <html xmlns="http://www.w3.org/1999/xhtml">
      <head>
        <meta name="color-scheme" content="light dark">
        <meta name="supported-color-schemes" content="light dark">
        <style>
          :root { color-scheme: light dark; supported-color-schemes: light dark; }
          @media (prefers-color-scheme: dark) {
            .email-body { background-color: #1a1a2e !important; }
            .email-card { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%) !important; border: 1px solid #334155 !important; }
            .email-heading { color: #f1f5f9 !important; }
            .email-name { color: #fbbf24 !important; }
            .email-text { color: #cbd5e1 !important; }
            .email-subtext { color: #94a3b8 !important; }
            .email-btn { background: #fbbf24 !important; color: #0f172a !important; }
            .email-footer { color: #64748b !important; }
          }
        </style>
      </head>
      <body style="margin:0;padding:0;">
      <div class="email-body" style="max-width:600px;margin:0 auto;padding:20px 10px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background-color:#f3f4f6;">
        <div class="email-card" style="background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);border-radius:16px;padding:24px 16px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,0.15);position:relative;overflow:hidden;">
          <div style="position:relative;z-index:1;">
            <h1 class="email-heading" style="color:#ffffff;margin:0 0 12px 0;font-size:22px;font-weight:700;letter-spacing:-0.5px;">
              Hi <span class="email-name" style="color:#ffd700;text-shadow:0 0 8px rgba(255,215,0,0.6);">${name || 'there'}</span>,
            </h1>
            <p class="email-text" style="color:rgba(255,255,255,0.95);font-size:14px;line-height:1.5;margin:0 0 12px 0;max-width:380px;margin-left:auto;margin-right:auto;">
              We received a request to reset the password for your Entertainment World account.
            </p>
            <p class="email-text" style="color:rgba(255,255,255,0.95);font-size:14px;line-height:1.5;margin:0 0 20px 0;max-width:380px;margin-left:auto;margin-right:auto;">
              Click the button below to choose a new password. This link will expire in 10 minutes.
            </p>
            <a href="${resetUrl}" class="email-btn" style="display:inline-block;padding:12px 32px;background:#fbbf24;color:#111827;font-weight:700;font-size:14px;border-radius:9999px;text-decoration:none;box-shadow:0 6px 20px rgba(251,191,36,0.4);">
              Reset Password
            </a>
            <p class="email-subtext" style="color:rgba(255,255,255,0.75);font-size:12px;margin:20px 0 0 0;">
              If you did not request a password reset, you can safely ignore this email.
            </p>
          </div>
        </div>
        <p class="email-footer" style="text-align:center;color:#6b7280;font-size:11px;margin-top:16px;line-height:1.4;">
          This email was sent by Entertainment World. For security reasons, this reset link will expire shortly.
        </p>
      </div>
      </body>
      </html>
    `;
}

async function sendPasswordResetEmail(email, name, resetUrl) {
    const sendSmtpEmail = new brevoSdk.SendSmtpEmail();
    sendSmtpEmail.to = [{ email }];
    sendSmtpEmail.sender = { email: process.env.BREVO_SENDER_EMAIL, name: process.env.BREVO_SENDER_NAME || 'Entertainment World' };
    sendSmtpEmail.subject = 'Reset your Entertainment World password';
    sendSmtpEmail.htmlContent = buildPasswordResetEmailHtml(name, resetUrl);
    await brevoEmailApi.sendTransacEmail(sendSmtpEmail);
}

async function consumeRateLimit(ip) {
    return rateLimiter.consume(ip);
}

async function getLocationFromIP(ipString) {
    if (!ipString) return 'Unknown Location';
    
    // Split on comma in case of proxy headers like x-forwarded-for
    const ip = ipString.split(',')[0].trim();

    // Loopback / private IP detection
    if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('::ffff:127.0.0.1') || ip.startsWith('fe80') || ip.startsWith('10.') || ip.startsWith('192.168.')) {
        return 'Local Network';
    }

    try {
        // Fetch geolocation from ip-api.com (free, no sign up)
        const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,city`, {
            timeout: 5000
        });
        
        if (response.data && response.data.status === 'success') {
            const { city, country } = response.data;
            if (city && country) {
                return `${city}, ${country}`;
            }
            return country || city || 'Unknown Location';
        }
        return 'Unknown Location';
    } catch (error) {
        console.error(`Geo-IP Lookup failed for ${ip}:`, error.message);
        return 'Unknown Location';
    }
}

module.exports = {
    downloadAndOptimizeAvatar,
    createToken,
    formatUserResponse,
    generateVerificationToken,
    buildVerifyUrl,
    sendVerificationEmail,
    consumeRateLimit,
    rateLimiter,
    buildPasswordResetEmailHtml,
    sendPasswordResetEmail,
    parseUserAgent,
    getLocationFromIP,
};
