const RESERVED_USERNAMES = new Set([
  'admin', 'administrator', 'root', 'system', 'api', 'profile', 'user', 'users',
  'settings', 'login', 'register', 'auth', 'friends', 'movies', 'tvshows',
  'watchlist', 'help', 'terms', 'privacy', 'about', 'contact', 'search',
  'notifications', 'chat', 'room', 'game', 'streaming', 'stream', 'dashboard',
  'account', 'me', 'explore', 'feed', 'saved-streams', 'streaming-lobby', 'null', 'undefined'
]);

// Strip Vietnamese accents and normalize string
function removeAccents(str) {
  if (!str) return '';
  return str
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/đ/g, 'd')
    .replace(/Đ/g, 'D');
}

/**
 * Clean a raw name or email into a valid base username slug
 * @param {string} rawName
 * @param {string} [email]
 * @returns {string}
 */
function cleanBaseUsername(rawName, email = '') {
  let base = rawName;
  if (!base && email) {
    base = email.split('@')[0];
  }
  if (!base) base = 'user';

  base = removeAccents(base).toLowerCase().trim();
  // Replace all non-alphanumeric (except underscore and dot) with underscore
  base = base.replace(/[^a-z0-9_.]/g, '_').replace(/_+/g, '_').replace(/^_+|_+$/g, '');

  if (base.length < 3) {
    base = base ? `${base}_user` : 'user';
  }
  return base.slice(0, 20);
}

/**
 * Validate if a username is allowed
 * @param {string} username
 * @returns {{ valid: boolean, message?: string }}
 */
function validateUsername(username) {
  if (!username || typeof username !== 'string') {
    return { valid: false, message: 'Username is required' };
  }

  const normalized = username.toLowerCase().trim();

  if (normalized.length < 3) {
    return { valid: false, message: 'Username must be at least 3 characters' };
  }

  if (normalized.length > 25) {
    return { valid: false, message: 'Username must not exceed 25 characters' };
  }

  if (!/^[a-z0-9_.]+$/.test(normalized)) {
    return { valid: false, message: 'Username can only contain lowercase letters, numbers, underscores (_), and dots (.)' };
  }

  // Cannot start or end with a dot or underscore
  if (/^[._]|[._]$/.test(normalized)) {
    return { valid: false, message: 'Username cannot start or end with a dot or underscore' };
  }

  // Cannot be purely numbers
  if (/^\d+$/.test(normalized)) {
    return { valid: false, message: 'Username cannot consist of numbers only' };
  }

  if (RESERVED_USERNAMES.has(normalized)) {
    return { valid: false, message: 'This username is reserved and cannot be used' };
  }

  return { valid: true };
}

/**
 * Generate a guaranteed unique username in the database
 * @param {string} name
 * @param {string} email
 * @param {import('mongoose').Model} UserModel
 * @returns {Promise<string>}
 */
async function generateUniqueUsername(name, email, UserModel) {
  const base = cleanBaseUsername(name, email);
  let candidate = base;

  // If candidate is reserved, append a random number
  if (RESERVED_USERNAMES.has(candidate)) {
    candidate = `${candidate}_${Math.floor(100 + Math.random() * 900)}`;
  }

  // Check if available
  const existing = await UserModel.findOne({ username: candidate });
  if (!existing) {
    return candidate;
  }

  // Loop with random suffix until unique
  let attempts = 0;
  while (attempts < 50) {
    const randomSuffix = Math.floor(10 + Math.random() * 990);
    const suffixed = `${base.slice(0, 18)}_${randomSuffix}`;
    const exists = await UserModel.findOne({ username: suffixed });
    if (!exists) {
      return suffixed;
    }
    attempts++;
  }

  // Fallback with timestamp
  return `${base.slice(0, 14)}_${Date.now().toString().slice(-6)}`;
}

module.exports = {
  RESERVED_USERNAMES,
  cleanBaseUsername,
  validateUsername,
  generateUniqueUsername,
};
