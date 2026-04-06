const { validationResult } = require('express-validator');
const Comment = require('../models/Comment');
const User = require('../models/User');

// Middleware to validate request
const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

// GET /api/comments/top - Lấy top comments (most liked or most replied) for homepage
const getTopComments = async (req, res) => {
    try {
        const { limit = 10, sortBy = 'likes' } = req.query;
        const limitNum = Math.min(Math.max(parseInt(limit, 10), 1), 50);

        // Build aggregation pipeline
        const pipeline = [
            // Only get top-level comments that are not deleted
            { $match: { parentId: null, isDeleted: false } },

            // Add reply count field
            {
                $addFields: {
                    replyCount: { $size: { $ifNull: ['$replies', []] } }
                }
            },

            // Filter: must have at least 1 like OR 1 reply
            {
                $match: {
                    $or: [
                        { likes: { $gte: 1 } },
                        { replyCount: { $gte: 1 } }
                    ]
                }
            },

            // Sort by likes or reply count
            {
                $sort: sortBy === 'replies'
                    ? { replyCount: -1, createdAt: -1 }
                    : { likes: -1, createdAt: -1 }
            },

            // Limit results
            { $limit: limitNum },

            // Lookup user info
            {
                $lookup: {
                    from: 'users',
                    localField: 'userId',
                    foreignField: '_id',
                    as: 'user'
                }
            },

            // Unwind user array
            { $unwind: '$user' },

            // Project final shape
            {
                $project: {
                    _id: 1,
                    movieId: 1,
                    type: 1,
                    content: 1,
                    likes: 1,
                    replyCount: 1,
                    createdAt: 1,
                    'user.name': 1,
                    'user.avatar': 1,
                    'user.isEmailVerified': 1
                }
            }
        ];

        const comments = await Comment.aggregate(pipeline);

        res.json({
            success: true,
            data: comments
        });
    } catch (error) {
        console.error('Get top comments error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// GET /api/comments/recent - Lấy recent comments (newest across all movies) for homepage
const getRecentComments = async (req, res) => {
    try {
        const { limit = 10 } = req.query;
        const limitNum = Math.min(Math.max(parseInt(limit, 10), 1), 50);

        // Build aggregation pipeline for recent comments
        const pipeline = [
            // Only get top-level comments that are not deleted
            { $match: { parentId: null, isDeleted: false } },

            // Sort by creation date (newest first)
            { $sort: { createdAt: -1 } },

            // Limit results
            { $limit: limitNum },

            // Lookup user info
            {
                $lookup: {
                    from: 'users',
                    localField: 'userId',
                    foreignField: '_id',
                    as: 'user'
                }
            },

            // Unwind user array
            { $unwind: '$user' },

            // Project final shape
            {
                $project: {
                    _id: 1,
                    movieId: 1,
                    type: 1,
                    content: 1,
                    createdAt: 1,
                    'user.name': 1,
                    'user.avatar': 1,
                    'user.isEmailVerified': 1
                }
            }
        ];

        const comments = await Comment.aggregate(pipeline);

        res.json({
            success: true,
            data: comments
        });
    } catch (error) {
        console.error('Get recent comments error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// GET /api/comments/user/me - Lấy comments của user hiện tại
const getUserComments = async (req, res) => {
    try {
        const userId = req.user;
        const page = Math.max(parseInt(req.query.page || '1', 10), 1);
        const limit = Math.min(Math.max(parseInt(req.query.limit || '20', 10), 1), 50);
        const skip = (page - 1) * limit;

        const filter = req.query.filter || 'comments';
        let query = { isDeleted: false };
        if (filter === 'liked') {
            query.likedBy = userId;
        } else if (filter === 'replies') {
            query.userId = userId;
            query.parentId = { $ne: null };
        } else {
            query.userId = userId;
            query.parentId = null;
        }

        const [total, comments] = await Promise.all([
            Comment.countDocuments(query),
            Comment.find(query)
                .populate('userId', 'name email avatar')
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .lean()
        ]);

        const data = comments.map(c => {
            const liked = c.likedBy?.some(id => id.equals?.(userId));
            const { likedBy, ...rest } = c;
            return {
                ...rest,
                isLiked: liked
            };
        });

        res.json({
            success: true,
            data,
            total,
            page,
            limit,
            totalPages: Math.ceil(total / limit)
        });
    } catch (error) {
        console.error('Get user comments error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// GET /api/comments/:movieId/:type - Lấy comments với phân trang, sort DB-side và batched replies
const getCommentsByMovie = async (req, res) => {
    try {
        const { movieId, type } = req.params;
        const { sortBy = 'newest' } = req.query;
        const userId = req.user; // From auth middleware if authenticated

        if (!movieId || !type) {
            return res.status(400).json({ message: 'Movie ID and type are required' });
        }

        if (!['movie', 'tvshow'].includes(type)) {
            return res.status(400).json({ message: 'Type must be either movie or tvshow' });
        }

        // Pagination params
        const page = Math.max(parseInt(req.query.page || '1', 10), 1);
        const limit = Math.min(Math.max(parseInt(req.query.limit || '20', 10), 1), 50);
        const skip = (page - 1) * limit;

        // Sort mapping
        let sortQuery;
        switch (sortBy) {
            case 'oldest':
                sortQuery = { createdAt: 1 };
                break;
            case 'popular':
                sortQuery = { likes: -1, createdAt: -1 };
                break;
            case 'newest':
            default:
                sortQuery = { createdAt: -1 };
                break;
        }

        // Total count of top-level comments
        const [total, topLevel] = await Promise.all([
            Comment.countDocuments({ movieId: Number(movieId), type, parentId: null, isDeleted: false }),
            Comment.find({ movieId: Number(movieId), type, parentId: null, isDeleted: false })
                .populate('userId', 'name email avatar')
                .sort(sortQuery)
                .skip(skip)
                .limit(limit)
                .lean()
        ]);

        const topIds = topLevel.map(c => c._id);

        // Batched fetch of replies for current page comments
        const replies = topIds.length
            ? await Comment.find({ parentId: { $in: topIds }, isDeleted: false })
                .populate('userId', 'name email avatar')
                .sort({ createdAt: 1 })
                .lean()
            : [];

        // Group replies by parentId
        const repliesByParent = new Map();
        for (const r of replies) {
            // compute isLiked and strip likedBy
            const liked = userId ? r.likedBy?.some(id => id.equals?.(userId)) : false;
            delete r.likedBy;
            const arr = repliesByParent.get(String(r.parentId)) || [];
            arr.push({ ...r, isLiked: liked });
            repliesByParent.set(String(r.parentId), arr);
        }

        // Compose final list, compute isLiked for top-level, strip likedBy
        const data = topLevel.map(c => {
            const liked = userId ? c.likedBy?.some(id => id.equals?.(userId)) : false;
            const { likedBy, ...rest } = c;
            return {
                ...rest,
                isLiked: liked,
                replies: repliesByParent.get(String(c._id)) || []
            };
        });

        res.json({
            success: true,
            data,
            total,
            page,
            limit,
            totalPages: Math.ceil(total / limit)
        });
    } catch (error) {
        console.error('Get comments error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// POST /api/comments - Tạo comment mới
const createComment = async (req, res) => {
    try {
        const { movieId, type, content, parentId } = req.body;
        const userId = req.user;

        // Get user info
        const user = await User.findById(userId).select('name email avatar');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // If it's a reply, check if parent comment exists
        if (parentId) {
            const parentComment = await Comment.findById(parentId);
            if (!parentComment) {
                return res.status(404).json({ message: 'Parent comment not found' });
            }
        }

        const comment = new Comment({
            movieId: parseInt(movieId),
            type,
            userId,
            content: content.trim(),
            parentId: parentId || null
        });

        await comment.save();

        // If it's a reply, add to parent's replies array
        if (parentId) {
            await Comment.findByIdAndUpdate(parentId, {
                $push: { replies: comment._id }
            });
        }

        // Populate user info for response
        const populatedComment = await Comment.findById(comment._id)
            .populate('userId', 'name email avatar')
            .lean();

        res.status(201).json({
            success: true,
            message: 'Comment created successfully',
            data: {
                ...populatedComment,
                isLiked: false,
                likedBy: undefined
            }
        });
    } catch (error) {
        console.error('Create comment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// PUT /api/comments/:id/like - Toggle like cho comment
const toggleLike = async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user;

        const comment = await Comment.findById(id);
        if (!comment) {
            return res.status(404).json({ message: 'Comment not found' });
        }

        await comment.toggleLike(userId);

        const updatedComment = await Comment.findById(id)
            .populate('userId', 'name email avatar')
            .lean();

        res.json({
            success: true,
            message: 'Like toggled successfully',
            data: {
                ...updatedComment,
                isLiked: updatedComment.likedBy.some(id => id.equals(userId)),
                likedBy: undefined
            }
        });
    } catch (error) {
        console.error('Toggle like error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// PUT /api/comments/:id - Cập nhật nội dung comment
const updateComment = async (req, res) => {
    try {
        const { id } = req.params;
        const { content } = req.body;
        const userId = req.user;

        const comment = await Comment.findById(id);
        if (!comment) {
            return res.status(404).json({ message: 'Comment not found' });
        }

        // Chỉ chủ sở hữu mới được sửa
        if (!comment.userId.equals(userId)) {
            return res
                .status(403)
                .json({ message: 'You can only edit your own comments' });
        }

        comment.content = content.trim();
        await comment.save();

        const updated = await Comment.findById(id)
            .populate('userId', 'name email avatar')
            .lean();

        res.json({
            success: true,
            message: 'Comment updated successfully',
            data: {
                ...updated,
                likedBy: undefined,
            },
        });
    } catch (error) {
        console.error('Update comment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// DELETE /api/comments/:id - Xóa comment (soft delete)
const deleteComment = async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user;

        const comment = await Comment.findById(id);
        if (!comment) {
            return res.status(404).json({ message: 'Comment not found' });
        }

        // Check if user owns the comment
        if (!comment.userId.equals(userId)) {
            return res.status(403).json({ message: 'You can only delete your own comments' });
        }

        // HARD DELETE with simple cascading for replies
        if (!comment.parentId) {
            // Delete all replies of this top-level comment
            await Comment.deleteMany({ parentId: id });
        } else {
            // Pull this reply reference out of parent.replies
            await Comment.findByIdAndUpdate(comment.parentId, { $pull: { replies: comment._id } });
        }

        await Comment.deleteOne({ _id: id });

        res.json({
            success: true,
            message: 'Comment deleted successfully'
        });
    } catch (error) {
        console.error('Delete comment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// GET /api/comments/:id/replies - Lấy replies của một comment
const getReplies = async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user; // From auth middleware if authenticated

        const replies = await Comment.find({
            parentId: id,
            isDeleted: false
        })
            .populate('userId', 'name email avatar')
            .sort({ createdAt: 1 })
            .lean();

        const processedReplies = replies.map(reply => ({
            ...reply,
            isLiked: userId ? reply.likedBy.some(id => id.equals(userId)) : false,
            likedBy: undefined
        }));

        res.json({
            success: true,
            data: processedReplies
        });
    } catch (error) {
        console.error('Get replies error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

module.exports = {
    validateRequest,
    getTopComments,
    getRecentComments,
    getUserComments,
    getCommentsByMovie,
    createComment,
    toggleLike,
    updateComment,
    deleteComment,
    getReplies
};
