const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true
    // Removed unique: true to allow same email for different auth types
  },
  password: {
    type: String,
    required: function () {
      return this.authType === 'email';
    },
    minlength: 6
  },
  avatar: {
    type: String,
    default: ''
  },
  originalAvatar: {
    type: String,
    default: '',
    // Avatar gốc từ Google, không thay đổi
  },
  authType: {
    type: String,
    required: true,
    enum: ['email', 'google'],
    default: 'email'
  },
  providerId: {
    type: String,
    required: function () {
      return this.authType !== 'email';
    }
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: {
    type: String,
    default: ''
  },
  watchlist: [
    {
      id: { type: Number, required: true },
      title: { type: String, required: true },
      poster_path: { type: String, required: true },
      type: { type: String, enum: ['movie', 'tv'], default: 'movie' }
    }
  ],
  friends: [
    { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  ],
  friendRequests: [
    { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  ],
  sentFriendRequests: [
    { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  ],
  createdAt: {
    type: Date,
    default: Date.now
  },
  passwordChangedAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

// Compound index to ensure unique email per auth type
// Note: This index might cause issues with existing users, so we handle uniqueness in application logic
// userSchema.index({ email: 1, authType: 1 }, { unique: true });

// Hash password before saving (only for email auth type)
userSchema.pre('save', async function (next) {
  if (!this.isModified('password') || this.authType !== 'email') return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    this.passwordChangedAt = new Date();
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password (only for email auth type)
userSchema.methods.comparePassword = async function (candidatePassword) {
  if (this.authType !== 'email') {
    throw new Error('Password comparison only available for email authentication');
  }
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

module.exports = User; 