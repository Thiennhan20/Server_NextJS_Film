const Notification = require('../models/Notification');
const User = require('../models/User');
const notificationService = require('../services/notificationService');

const getNotifications = async (req, res) => {
  try {
    const userId = req.user;
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit || '20', 10), 1), 50);
    const skip = (page - 1) * limit;

    await notificationService.cleanupStaleCommentNotifications(userId);

    const query = { recipient: userId };

    const [total, unreadCount, notifications] = await Promise.all([
      Notification.countDocuments(query),
      Notification.countDocuments({ ...query, read: false }),
      Notification.find(query)
        .populate('actor', 'name avatar')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean()
    ]);

    res.json({
      success: true,
      data: notifications,
      unreadCount,
      total,
      page,
      totalPages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Get notifications error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const getUnreadCount = async (req, res) => {
  try {
    await notificationService.cleanupStaleCommentNotifications(req.user);

    const unreadCount = await Notification.countDocuments({
      recipient: req.user,
      read: false
    });

    res.json({ success: true, unreadCount });
  } catch (error) {
    console.error('Get unread notifications error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const markAsRead = async (req, res) => {
  try {
    const notification = await Notification.findOneAndUpdate(
      { _id: req.params.id, recipient: req.user },
      { $set: { read: true, readAt: new Date() } },
      { new: true }
    )
      .populate('actor', 'name avatar')
      .lean();

    if (!notification) {
      return res.status(404).json({ message: 'Notification not found' });
    }

    res.json({ success: true, data: notification });
  } catch (error) {
    console.error('Mark notification read error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const getNotificationTarget = async (req, res) => {
  try {
    const notification = await Notification.findOne({
      _id: req.params.id,
      recipient: req.user
    }).lean();

    if (!notification) {
      return res.status(404).json({ message: 'Notification not found' });
    }

    const target = await notificationService.resolveNotificationTarget(notification);
    if (!target) {
      return res.status(404).json({ message: 'Notification target not found' });
    }

    res.json({ success: true, data: target });
  } catch (error) {
    console.error('Get notification target error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const markAllAsRead = async (req, res) => {
  try {
    const result = await Notification.updateMany(
      { recipient: req.user, read: false },
      { $set: { read: true, readAt: new Date() } }
    );

    res.json({
      success: true,
      modifiedCount: result.modifiedCount || 0
    });
  } catch (error) {
    console.error('Mark all notifications read error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const registerPushToken = async (req, res) => {
  try {
    const { token } = req.body;
    if (!token || typeof token !== 'string') {
      return res.status(400).json({ message: 'Valid push token is required' });
    }

    // $addToSet prevents duplicates
    await User.findByIdAndUpdate(req.user, {
      $addToSet: { pushTokens: token.trim() }
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Register push token error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const deregisterPushToken = async (req, res) => {
  try {
    const { token } = req.body;
    if (!token || typeof token !== 'string') {
      return res.status(400).json({ message: 'Valid push token is required' });
    }

    await User.findByIdAndUpdate(req.user, {
      $pull: { pushTokens: token.trim() }
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Deregister push token error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = {
  getNotifications,
  getUnreadCount,
  getNotificationTarget,
  markAsRead,
  markAllAsRead,
  registerPushToken,
  deregisterPushToken
};
