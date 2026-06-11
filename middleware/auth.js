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

    // Check if token exists in blacklist
    const isBlacklisted = await BlacklistedToken.findOne({ token });
    if (isBlacklisted) {
      // Nếu token bị blacklist nhưng vẫn có refreshToken → cho client refresh
      if (req.cookies?.refreshToken) {
        return res.status(401).json({ message: 'Token has been invalidated', code: 'TOKEN_EXPIRED' });
      }
      return res.status(401).json({ message: 'Token has been invalidated' });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check if session is active
    if (decoded.sessionId) {
      const Session = require('../models/Session');
      const sessionExists = await Session.exists({ _id: decoded.sessionId });
      if (!sessionExists) {
        return res.status(401).json({ message: 'Session has been revoked', code: 'SESSION_REVOKED' });
      }
    }

    const User = require('../models/User');
    const user = await User.findById(decoded.userId);
    
    // Kiểm tra user tồn tại
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    // Invalidate tokens issued before password was changed
    if (user.passwordChangedAt && decoded.iat && decoded.iat * 1000 < user.passwordChangedAt.getTime()) {
      // Nếu có refreshToken → cho client refresh với token mới
      if (req.cookies?.refreshToken) {
        return res.status(401).json({ message: 'Token has been invalidated', code: 'TOKEN_EXPIRED' });
      }
      return res.status(401).json({ message: 'Token has been invalidated' });
    }
    
    req.user = decoded.userId; // Chỉ gán userId để tương thích với code hiện tại
    req.token = token; // Attach token to request (for logout later)
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