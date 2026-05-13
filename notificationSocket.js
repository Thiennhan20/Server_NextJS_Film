const jwt = require('jsonwebtoken');
const BlacklistedToken = require('./models/BlacklistedToken');
const User = require('./models/User');

function initializeNotificationSocket(io) {
  const notificationNamespace = io.of('/notifications');

  notificationNamespace.use(async (socket, next) => {
    const token = socket.handshake.auth?.token || socket.handshake.query?.token;

    if (!token) {
      return next(new Error('AUTH_ERROR: No token provided'));
    }

    try {
      const isBlacklisted = await BlacklistedToken.findOne({ token });
      if (isBlacklisted) {
        return next(new Error('AUTH_ERROR: Token has been invalidated'));
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.userId).select('_id name');
      if (!user) {
        return next(new Error('AUTH_ERROR: User not found'));
      }

      socket.userId = String(user._id);
      socket.username = user.name || 'User';
      next();
    } catch (err) {
      console.error('[Notifications] Auth error:', err.message);
      return next(new Error('AUTH_ERROR: Invalid or expired token'));
    }
  });

  notificationNamespace.on('connection', (socket) => {
    socket.join(`user:${socket.userId}`);
    console.log(`[Notifications] User connected: ${socket.username} (${socket.userId})`);

    socket.on('disconnect', () => {
      console.log(`[Notifications] User disconnected: ${socket.username} (${socket.userId})`);
    });
  });

  return notificationNamespace;
}

module.exports = initializeNotificationSocket;
