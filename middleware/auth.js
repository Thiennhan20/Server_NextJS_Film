const jwt = require('jsonwebtoken');
const BlacklistedToken = require('../models/BlacklistedToken');

const auth = async (req, res, next) => {
  try {
    let token = req.cookies?.token;
    
    if (!token) {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // Nếu có refreshToken cookie → access token hết hạn hoặc bị mất, client nên refresh
        if (req.cookies?.refreshToken) {
          return res.status(401).json({ message: 'Access token missing', code: 'TOKEN_EXPIRED' });
        }
        return res.status(401).json({ message: 'No authentication token found' });
      }
      token = authHeader.substring(7); // Bỏ 'Bearer ' prefix
    }

    // 1. Verify token first (synchronous CPU check - avoids DB round trips if expired or malformed)
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 2. Parallelize all database validation checks concurrently in a single round-trip
    const Session = require('../models/Session');
    const User = require('../models/User');

    const [isBlacklisted, sessionExists, user] = await Promise.all([
      BlacklistedToken.exists({ token }),
      decoded.sessionId ? Session.exists({ _id: decoded.sessionId }) : Promise.resolve(true),
      User.findById(decoded.userId).select('passwordChangedAt').lean()
    ]);

    if (isBlacklisted) {
      if (req.cookies?.refreshToken) {
        return res.status(401).json({ message: 'Token has been invalidated', code: 'TOKEN_EXPIRED' });
      }
      return res.status(401).json({ message: 'Token has been invalidated' });
    }

    if (decoded.sessionId && !sessionExists) {
      return res.status(401).json({ message: 'Session has been revoked', code: 'SESSION_REVOKED' });
    }

    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    // Invalidate tokens issued before password was changed
    if (user.passwordChangedAt && decoded.iat && decoded.iat * 1000 < new Date(user.passwordChangedAt).getTime()) {
      if (req.cookies?.refreshToken) {
        return res.status(401).json({ message: 'Token has been invalidated', code: 'TOKEN_EXPIRED' });
      }
      return res.status(401).json({ message: 'Token has been invalidated' });
    }
    
    req.user = decoded.userId;
    req.token = token;
    req.sessionId = decoded.sessionId;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    // Nếu token verify thất bại nhưng có refreshToken → cho client thử refresh
    if (req.cookies?.refreshToken) {
      return res.status(401).json({ message: 'Token invalid', code: 'TOKEN_EXPIRED' });
    }
    res.status(401).json({ message: 'Please authenticate' });
  }
};

module.exports = auth; 