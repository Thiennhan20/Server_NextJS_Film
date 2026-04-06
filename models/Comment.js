const mongoose = require('mongoose');

const commentSchema = new mongoose.Schema({
  movieId: {
    type: Number,
    required: true,
    index: true
  },
  type: {
    type: String,
    enum: ['movie', 'tvshow'],
    required: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    required: true,
    maxlength: 500
  },
  likes: {
    type: Number,
    default: 0
  },
  likedBy: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  parentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Comment',
    default: null
  },
  replies: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Comment'
  }],
  isDeleted: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

// Index for better query performance
commentSchema.index({ movieId: 1, type: 1, createdAt: -1 });
commentSchema.index({ parentId: 1 });
commentSchema.index({ userId: 1 });
commentSchema.index({ likedBy: 1 });

// Virtual for checking if user liked the comment
commentSchema.virtual('isLiked').get(function() {
  return this.likedBy && this.likedBy.length > 0;
});

// Method to toggle like
commentSchema.methods.toggleLike = function(userId) {
  const userObjectId = new mongoose.Types.ObjectId(userId);
  const likedIndex = this.likedBy.findIndex(id => id.equals(userObjectId));
  
  if (likedIndex > -1) {
    // User already liked, remove like
    this.likedBy.splice(likedIndex, 1);
    this.likes = Math.max(0, this.likes - 1);
  } else {
    // User hasn't liked, add like
    this.likedBy.push(userObjectId);
    this.likes += 1;
  }
  
  return this.save();
};

// Method to check if user liked the comment
commentSchema.methods.hasUserLiked = function(userId) {
  if (!userId) return false;
  const userObjectId = new mongoose.Types.ObjectId(userId);
  return this.likedBy.some(id => id.equals(userObjectId));
};

// Static method to get comments with user info
commentSchema.statics.getCommentsWithUserInfo = async function(movieId, type, userId = null) {
  const comments = await this.find({ 
    movieId, 
    type, 
    parentId: null, 
    isDeleted: false 
  })
  .populate('userId', 'name email avatar')
  .sort({ createdAt: -1 })
  .lean();

  // Get replies for each comment
  const commentsWithReplies = await Promise.all(
    comments.map(async (comment) => {
      const replies = await this.find({ 
        parentId: comment._id, 
        isDeleted: false 
      })
      .populate('userId', 'name email avatar')
      .sort({ createdAt: 1 })
      .lean();

      // Add user like status if userId provided
      const processedReplies = replies.map(reply => ({
        ...reply,
        isLiked: userId ? reply.likedBy.some(id => id.equals(userId)) : false,
        likedBy: undefined // Don't send likedBy array to client
      }));

      return {
        ...comment,
        isLiked: userId ? comment.likedBy.some(id => id.equals(userId)) : false,
        likedBy: undefined, // Don't send likedBy array to client
        replies: processedReplies
      };
    })
  );

  return commentsWithReplies;
};

const Comment = mongoose.model('Comment', commentSchema);

module.exports = Comment;
