const mongoose = require('mongoose');

const REPORT_REASONS = [
  'spam',
  'harassment',
  'hate_speech',
  'spoiler',
  'inappropriate',
  'other',
];

const userReportSchema = new mongoose.Schema({
  reporterId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  reporterName: {
    type: String,
    default: '',
    trim: true,
  },
  targetType: {
    type: String,
    enum: ['comment', 'user', 'content', 'room'],
    default: 'comment',
    required: true,
    index: true,
  },
  targetId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    index: true,
  },
  parentCommentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Comment',
    default: null,
  },
  reportedUserId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null,
    index: true,
  },
  reportedUserName: {
    type: String,
    default: '',
    trim: true,
  },
  movieId: {
    type: Number,
    default: null,
  },
  contentType: {
    type: String,
    enum: ['movie', 'tvshow', null],
    default: null,
  },
  targetDetail: {
    type: String,
    default: '',
    maxlength: 1000,
  },
  commentSnapshot: {
    content: { type: String, default: '', maxlength: 500 },
    authorName: { type: String, default: '' },
    authorUsername: { type: String, default: '' },
    commentCreatedAt: { type: Date, default: null },
  },
  reasonCategory: {
    type: String,
    enum: REPORT_REASONS,
    required: true,
  },
  details: {
    type: String,
    default: '',
    trim: true,
    maxlength: 300,
  },
  reason: {
    type: String,
    default: '',
    maxlength: 400,
  },
  status: {
    type: String,
    enum: ['pending', 'reviewing', 'resolved', 'dismissed'],
    default: 'pending',
    index: true,
  },
  actionTaken: {
    type: String,
    enum: ['none', 'comment_hidden', 'comment_deleted', 'user_banned'],
    default: 'none',
  },
  resolvedBy: {
    type: String,
    default: '',
  },
  resolutionNote: {
    type: String,
    default: '',
    maxlength: 500,
  },
  resolvedAt: {
    type: Date,
    default: null,
  },
}, {
  collection: 'userreports',
  timestamps: true,
});

userReportSchema.index({ targetType: 1, targetId: 1, reporterId: 1 }, { unique: true });
userReportSchema.index({ status: 1, createdAt: -1 });
userReportSchema.index({ targetId: 1, status: 1 });
userReportSchema.index({ reportedUserId: 1, createdAt: -1 });

const UserReport = mongoose.model('UserReport', userReportSchema);

module.exports = UserReport;
module.exports.REPORT_REASONS = REPORT_REASONS;

