const Hashids = require('hashids/cjs');

const salt = process.env.HASHID_SALT || process.env.JWT_SECRET || 'movie-web-hashid-salt-secret';
const hashids = new Hashids(salt, 10);

/**
 * Encode a MongoDB ObjectId (or 24-char hex string) to Hashids
 * @param {string|import('mongoose').Types.ObjectId} objectId
 * @returns {string|null}
 */
function encodeId(objectId) {
  if (!objectId) return null;
  const hex = objectId.toString();
  if (!/^[0-9a-fA-F]{24}$/.test(hex)) {
    return hex;
  }
  return hashids.encodeHex(hex);
}

/**
 * Decode a Hashids string or return the 24-char hex ObjectId if already hex
 * @param {string} hashOrId
 * @returns {string|null}
 */
function decodeId(hashOrId) {
  if (!hashOrId) return null;
  const str = String(hashOrId).trim();
  if (/^[0-9a-fA-F]{24}$/.test(str)) {
    return str;
  }
  try {
    const decoded = hashids.decodeHex(str);
    if (decoded && /^[0-9a-fA-F]{24}$/.test(decoded)) {
      return decoded;
    }
  } catch {
    // ignore decode error
  }
  return null;
}

module.exports = {
  encodeId,
  decodeId,
};
