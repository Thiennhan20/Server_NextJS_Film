const crypto = require('crypto');
require('dotenv').config();

/**
 * Middleware to secure Admin endpoints via a shared secret API Key (Machine-to-Machine authentication)
 * Accepts key via:
 * 1. Header 'x-admin-api-key'
 * 2. Header 'Authorization: Bearer <ADMIN_API_KEY>'
 */
const adminApiKey = (req, res, next) => {
  const configuredKey = process.env.ADMIN_API_KEY;

  if (!configuredKey) {
    console.error('[CRITICAL] ADMIN_API_KEY is not defined in server environment!');
    return res.status(500).json({ message: 'Server configuration error' });
  }

  // Check header 'x-admin-api-key' or 'authorization'
  let providedKey = req.headers['x-admin-api-key'];

  if (!providedKey && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
      providedKey = parts[1];
    }
  }

  if (!providedKey) {
    return res.status(401).json({ message: 'Unauthorized: Admin API key required' });
  }

  // Timing-safe comparison to prevent timing attacks
  const providedBuffer = Buffer.from(String(providedKey));
  const configuredBuffer = Buffer.from(String(configuredKey));

  if (
    providedBuffer.length !== configuredBuffer.length ||
    !crypto.timingSafeEqual(providedBuffer, configuredBuffer)
  ) {
    return res.status(403).json({ message: 'Forbidden: Invalid Admin API key' });
  }

  next();
};

module.exports = adminApiKey;
