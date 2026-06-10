const jwt = require('jsonwebtoken');

const optionalAuth = async (req, res, next) => {
  try {
    let token = req.cookies?.token;
    
    if (!token) {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }
    }
    
    if (token) {
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
