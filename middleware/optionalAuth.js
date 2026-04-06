const jwt = require('jsonwebtoken');

const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      
      const BlacklistedToken = require('../models/BlacklistedToken');
      const isBlacklisted = await BlacklistedToken.findOne({ token });
      
      if (!isBlacklisted) {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.userId; 
      }
    }
    next();
  } catch (error) {
    // If token is invalid, ignore and proceed as anonymous
    next();
  }
};

module.exports = optionalAuth;
