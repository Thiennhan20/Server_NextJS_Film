const Notification = require('../models/Notification');
const Comment = require('../models/Comment');
const User = require('../models/User');
const axios = require('axios');

const COMMENT_NOTIFICATION_TYPES = ['comment_liked', 'comment_replied'];
const EXPO_PUSH_URL = 'https://exp.host/--/api/v2/push/send';

function normalizeId(id) {
  return id ? String(id) : '';
}

function escapeRegex(value = '') {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function getPushTitle(type, actorName) {
  switch (type) {
    case 'comment_liked':
      return 'Bình luận được thích ❤️';
    case 'comment_replied':
      return 'Phản hồi bình luận 💬';
    case 'friend_request':
      return 'Lời mời kết bạn 👋';
    case 'friend_accept':
      return 'Đồng ý kết bạn ✅';
    default:
      return 'Thông báo mới';
  }
}

function getPushBody(type, actorName, metadata) {
  switch (type) {
    case 'comment_liked':
      return `${actorName} đã thích bình luận của bạn.`;
    case 'comment_replied':
      return `${actorName} đã trả lời bình luận của bạn.`;
    case 'friend_request':
      return `${actorName} đã gửi lời mời kết bạn.`;
    case 'friend_accept':
      return `${actorName} đã đồng ý lời mời kết bạn.`;
    default:
      return 'Bạn có một thông báo mới.';
  }
}

async function sendPushNotification(recipientId, serializedNotification) {
  try {
    const user = await User.findById(recipientId).select('pushTokens').lean();
    if (!user || !user.pushTokens || user.pushTokens.length === 0) return;

    const actorName = serializedNotification?.actor?.name || 'Ai đó';
    const type = serializedNotification?.type || '';
    const metadata = serializedNotification?.metadata || {};

    const title = getPushTitle(type, actorName);
    const body = getPushBody(type, actorName, metadata);

    // Build messages for each registered token
    const messages = user.pushTokens
      .filter((token) => typeof token === 'string' && token.startsWith('ExponentPushToken'))
      .map((token) => ({
        to: token,
        sound: 'default',
        title,
        body,
        data: {
          notificationId: serializedNotification?._id ? String(serializedNotification._id) : '',
          type,
        },
      }));

    if (messages.length === 0) return;

    // Send in chunks of 100 (Expo limit)
    for (let i = 0; i < messages.length; i += 100) {
      const chunk = messages.slice(i, i + 100);
      await axios.post(EXPO_PUSH_URL, chunk, {
        headers: {
          'Accept': 'application/json',
          'Accept-Encoding': 'gzip, deflate',
          'Content-Type': 'application/json',
        },
        timeout: 10000,
      });
    }
  } catch (error) {
    // Push notification failure should never block the main flow
    console.error('[Push] Failed to send push notification:', error.message);
  }
}

function pickClosestToNotification(comments, notification) {
  if (!comments || comments.length === 0) return null;

  const notificationTime = notification.createdAt
    ? new Date(notification.createdAt).getTime()
    : Date.now();

  return comments.reduce((closest, current) => {
    const closestTime = closest.updatedAt || closest.createdAt;
    const currentTime = current.updatedAt || current.createdAt;
    const closestDiff = Math.abs(new Date(closestTime).getTime() - notificationTime);
    const currentDiff = Math.abs(new Date(currentTime).getTime() - notificationTime);
    return currentDiff < closestDiff ? current : closest;
  });
}

async function serializeNotification(notificationId) {
  return Notification.findById(notificationId)
    .populate('actor', 'name avatar')
    .lean();
}

async function createNotification({ recipientId, actorId = null, type, metadata = {} }) {
  const recipient = normalizeId(recipientId);
  const actor = normalizeId(actorId);

  if (!recipient) return null;
  if (actor && actor === recipient) return null;

  const notification = await Notification.create({
    recipient: recipientId,
    actor: actorId || null,
    type,
    metadata
  });

  const serialized = await serializeNotification(notification._id);

  // Fire push notification in background (non-blocking)
  sendPushNotification(recipientId, serialized).catch(() => {});

  return serialized;
}

async function deleteNotificationsForComments(commentIds) {
  const ids = (commentIds || []).filter(Boolean);
  if (ids.length === 0) return { deletedCount: 0 };

  return Notification.deleteMany({
    type: { $in: COMMENT_NOTIFICATION_TYPES },
    $or: [
      { 'metadata.commentId': { $in: ids } },
      { 'metadata.parentCommentId': { $in: ids } }
    ]
  });
}

async function updateNotificationsForCommentPreview(commentId, preview = '') {
  const id = normalizeId(commentId);
  if (!id) return { modifiedCount: 0 };

  return Notification.updateMany(
    {
      type: { $in: COMMENT_NOTIFICATION_TYPES },
      'metadata.commentId': id
    },
    {
      $set: {
        'metadata.commentPreview': String(preview || '').substring(0, 160)
      }
    }
  );
}

async function cleanupStaleCommentNotifications(recipientId) {
  const recipient = normalizeId(recipientId);
  if (!recipient) return { deletedCount: 0 };

  const notifications = await Notification.find({
    recipient: recipientId,
    type: { $in: COMMENT_NOTIFICATION_TYPES }
  })
    .select('_id metadata.commentId metadata.parentCommentId')
    .lean();

  if (notifications.length === 0) return { deletedCount: 0 };

  const relatedIds = new Set();
  for (const notification of notifications) {
    if (notification.metadata?.commentId) {
      relatedIds.add(String(notification.metadata.commentId));
    }
    if (notification.metadata?.parentCommentId) {
      relatedIds.add(String(notification.metadata.parentCommentId));
    }
  }

  if (relatedIds.size === 0) return { deletedCount: 0 };

  const existingComments = await Comment.find({
    _id: { $in: Array.from(relatedIds) },
    isDeleted: false
  })
    .select('_id')
    .lean();

  const existingIds = new Set(existingComments.map((comment) => String(comment._id)));
  const staleNotificationIds = notifications
    .filter((notification) => {
      const commentId = notification.metadata?.commentId;
      const parentCommentId = notification.metadata?.parentCommentId;

      if (commentId && !existingIds.has(String(commentId))) return true;
      if (parentCommentId && !existingIds.has(String(parentCommentId))) return true;
      return false;
    })
    .map((notification) => notification._id);

  if (staleNotificationIds.length === 0) return { deletedCount: 0 };

  return Notification.deleteMany({ _id: { $in: staleNotificationIds } });
}

async function findNotificationCommentFallback(notification) {
  const metadata = notification.metadata || {};
  const movieId = Number(metadata.movieId);
  const contentType = metadata.contentType;
  const preview = String(metadata.commentPreview || '').trim();

  if (!movieId || !contentType) return null;

  const query = {
    movieId,
    type: contentType,
    isDeleted: false
  };

  if (preview) {
    query.content = { $regex: `^${escapeRegex(preview)}` };
  }

  if (notification.type === 'comment_replied') {
    const actorId = normalizeId(notification.actor);
    if (!actorId) return null;

    query.userId = notification.actor;
    query.parentId = { $ne: null };
  } else if (notification.type === 'comment_liked') {
    const recipientId = normalizeId(notification.recipient);
    if (!recipientId) return null;

    query.userId = notification.recipient;
  } else {
    return null;
  }

  const candidates = await Comment.find(query)
    .populate('userId', '_id')
    .sort({ createdAt: -1 })
    .limit(10)
    .lean();

  return pickClosestToNotification(
    candidates.filter((comment) => !!comment.userId),
    notification
  );
}

async function findLikedCommentTarget(notification) {
  const metadata = notification.metadata || {};
  const movieId = Number(metadata.movieId);
  const contentType = metadata.contentType;
  const preview = String(metadata.commentPreview || '').trim();
  const recipientId = normalizeId(notification.recipient);
  const actorId = normalizeId(notification.actor);

  if (!movieId || !contentType || !recipientId) return null;

  const query = {
    movieId,
    type: contentType,
    userId: notification.recipient,
    isDeleted: false
  };

  if (actorId) {
    query.likedBy = notification.actor;
  }

  if (preview) {
    query.content = { $regex: `^${escapeRegex(preview)}` };
  }

  const candidates = await Comment.find(query)
    .populate('userId', '_id')
    .sort({ updatedAt: -1 })
    .limit(20)
    .lean();

  return pickClosestToNotification(
    candidates.filter((comment) => !!comment.userId),
    notification
  );
}

async function resolveNotificationTarget(notification) {
  if (!notification || !COMMENT_NOTIFICATION_TYPES.includes(notification.type)) return null;

  const metadata = notification.metadata || {};
  const movieId = Number(metadata.movieId);
  const contentType = metadata.contentType;
  let commentId = metadata.commentId ? normalizeId(metadata.commentId) : '';
  let parentCommentId = metadata.parentCommentId ? normalizeId(metadata.parentCommentId) : '';

  if (!movieId || !contentType) return null;

  if (commentId || parentCommentId) {
    const ids = [commentId, parentCommentId].filter(Boolean);
    const existingComments = await Comment.find({
      _id: { $in: ids },
      isDeleted: false
    })
      .populate('userId', '_id')
      .select('_id userId parentId')
      .lean();

    const existingIds = new Set(
      existingComments
        .filter((comment) => !!comment.userId)
        .map((comment) => normalizeId(comment._id))
    );
    const commentsById = new Map(
      existingComments
        .filter((comment) => !!comment.userId)
        .map((comment) => [normalizeId(comment._id), comment])
    );

    if (commentId && !existingIds.has(commentId)) {
      commentId = '';
    }
    if (parentCommentId && !existingIds.has(parentCommentId)) {
      parentCommentId = '';
    }

    const targetComment = commentId ? commentsById.get(commentId) : null;

    if (notification.type === 'comment_replied') {
      if (targetComment?.parentId) {
        parentCommentId = normalizeId(targetComment.parentId);
      } else {
        commentId = '';
        parentCommentId = '';
      }
    }

    if (notification.type === 'comment_liked') {
      const likedTarget = await findLikedCommentTarget(notification);

      if (likedTarget) {
        commentId = normalizeId(likedTarget._id);
        parentCommentId = likedTarget.parentId ? normalizeId(likedTarget.parentId) : '';
      } else if (targetComment?.parentId) {
        parentCommentId = normalizeId(targetComment.parentId);
      }
    }
  }

  if (!commentId && !parentCommentId) {
    const fallbackComment = await findNotificationCommentFallback(notification);
    if (fallbackComment) {
      commentId = normalizeId(fallbackComment._id);
      parentCommentId = fallbackComment.parentId ? normalizeId(fallbackComment.parentId) : '';
      const metadataUpdate = {
        'metadata.commentId': fallbackComment._id
      };

      if (fallbackComment.parentId) {
        metadataUpdate['metadata.parentCommentId'] = fallbackComment.parentId;
      }

      await Notification.updateOne(
        { _id: notification._id },
        { $set: metadataUpdate }
      );
    }
  }

  if (!commentId && !parentCommentId) return null;

  const metadataSet = {};
  const metadataUnset = {};

  if (commentId && normalizeId(metadata.commentId) !== commentId) {
    metadataSet['metadata.commentId'] = commentId;
  }
  if (parentCommentId && normalizeId(metadata.parentCommentId) !== parentCommentId) {
    metadataSet['metadata.parentCommentId'] = parentCommentId;
  }
  if (!parentCommentId && metadata.parentCommentId) {
    metadataUnset['metadata.parentCommentId'] = '';
  }

  if (Object.keys(metadataSet).length > 0 || Object.keys(metadataUnset).length > 0) {
    const update = {};
    if (Object.keys(metadataSet).length > 0) update.$set = metadataSet;
    if (Object.keys(metadataUnset).length > 0) update.$unset = metadataUnset;
    await Notification.updateOne({ _id: notification._id }, update);
  }

  return {
    movieId,
    contentType,
    commentId: commentId || parentCommentId,
    parentCommentId: parentCommentId || undefined
  };
}

module.exports = {
  createNotification,
  deleteNotificationsForComments,
  updateNotificationsForCommentPreview,
  cleanupStaleCommentNotifications,
  resolveNotificationTarget
};
