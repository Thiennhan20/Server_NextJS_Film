const mongoose = require('mongoose');

const SessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  refreshToken: {
    type: String,
    required: true,
    unique: true
  },
  userAgent: {
    type: String,
    default: ''
  },
  device: {
    type: String,
    default: 'Unknown Device'
  },
  ip: {
    type: String,
    default: ''
  },
  lastActive: {
    type: Date,
    default: Date.now
  },
  expiresAt: {
    type: Date,
    required: true
  }
}, {
  timestamps: true
});

// TTL index to automatically expire sessions at expiresAt
SessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const Session = mongoose.model('Session', SessionSchema);
module.exports = Session;
