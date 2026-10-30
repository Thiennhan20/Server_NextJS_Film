const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  actor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  type: {
    type: String,
    enum: ['comment_liked', 'comment_replied', 'version_updated', 'friend_request', 'friend_accept', 'room_invite'],
    required: true,
    index: true
  },
  read: {
    type: Boolean,
    default: false,
    index: true
  },
  readAt: {
    type: Date,
    default: null
  },
  metadata: {
    movieId: Number,
    contentType: {
      type: String,
      enum: ['movie', 'tvshow']
    },
    roomId: String,
    roomTitle: String,
    roomPin: String,
    poster: String,
    commentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Comment'
    },
    parentCommentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Comment'
    },
    commentPreview: {
      type: String,
      maxlength: 160
    },
    versionHash: String,
    versionMessage: String,
    expiresAt: Date
  },
  expiresAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

notificationSchema.index({ recipient: 1, read: 1, createdAt: -1 });
notificationSchema.index({ recipient: 1, createdAt: -1 });
notificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
notificationSchema.index({ type: 1, 'metadata.roomId': 1 });

const Notification = mongoose.model('Notification', notificationSchema);

module.exports = Notification;
