const { validationResult } = require('express-validator');
const Comment = require('../models/Comment');
const User = require('../models/User');
const notificationService = require('../services/notificationService');

// Middleware to validate request
const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

const createNotificationSafely = async (payload) => {
    try {
        await notificationService.createNotification(payload);
    } catch (error) {
        console.warn('Create notification failed:', error.message);
    }
};

const buildCommentUserLookupStages = () => ([
    {
        $lookup: {
            from: 'users',
            localField: 'userId',
            foreignField: '_id',
            as: 'userDoc'
        }
    },
    { $unwind: '$userDoc' }
]);

const buildPopulateUserShapeStages = () => ([
    {
        $addFields: {
            userId: {
                _id: '$userDoc._id',
                name: '$userDoc.name',
                avatar: '$userDoc.avatar'
            }
        }
    },
    { $project: { userDoc: 0 } }
]);

const isLikedByUser = (comment, userId) => (
    userId ? comment.likedBy?.some(id => id.equals?.(userId) || String(id) === String(userId)) : false
);

const serializeComment = (comment, userId) => {
    const { likedBy, ...rest } = comment;
    return {
        ...rest,
        isLiked: isLikedByUser(comment, userId)
    };
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
                .populate('userId', 'name avatar')
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

        const topLevelMatch = { movieId: Number(movieId), type, parentId: null, isDeleted: false };
        const userLookupStages = buildCommentUserLookupStages();

        // Total count of top-level comments whose author account still exists
        const [totalResult, topLevel] = await Promise.all([
            Comment.aggregate([
                { $match: topLevelMatch },
                ...userLookupStages,
                { $count: 'total' }
            ]),
            Comment.aggregate([
                { $match: topLevelMatch },
                ...userLookupStages,
                ...buildPopulateUserShapeStages(),
                { $sort: sortQuery },
                { $skip: skip },
                { $limit: limit }
            ])
        ]);

        const total = totalResult[0]?.total || 0;

        const topIds = topLevel.map(c => c._id);

        // Batched fetch of replies for current page comments
        const replies = topIds.length
            ? await Comment.find({ parentId: { $in: topIds }, isDeleted: false })
                .populate('userId', 'name avatar')
                .sort({ createdAt: 1 })
                .lean()
            : [];

        // Group replies by parentId
        const repliesByParent = new Map();
        for (const r of replies.filter(reply => !!reply.userId)) {
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

// GET /api/comments/thread/:id - Lấy trực tiếp comment cha và replies cho deep link notification
const getCommentThread = async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user;

        const targetComment = await Comment.findOne({
            _id: id,
            isDeleted: false
        })
            .populate('userId', 'name avatar')
            .lean();

        if (!targetComment || !targetComment.userId) {
            return res.status(404).json({ message: 'Comment not found' });
        }

        const parentId = targetComment.parentId || targetComment._id;
        const parentComment = targetComment.parentId
            ? await Comment.findOne({
                _id: parentId,
                parentId: null,
                isDeleted: false
            })
                .populate('userId', 'name avatar')
                .lean()
            : targetComment;

        if (!parentComment || !parentComment.userId) {
            return res.status(404).json({ message: 'Parent comment not found' });
        }

        const replies = await Comment.find({
            parentId: parentComment._id,
            isDeleted: false
        })
            .populate('userId', 'name avatar')
            .sort({ createdAt: 1 })
            .lean();

        const processedReplies = replies
            .filter(reply => !!reply.userId)
            .map(reply => serializeComment(reply, userId));

        res.json({
            success: true,
            data: {
                ...serializeComment(parentComment, userId),
                replies: processedReplies
            },
            targetCommentId: String(targetComment._id),
            parentCommentId: String(parentComment._id)
        });
    } catch (error) {
        console.error('Get comment thread error:', error);
        res.status(500).json({ message: 'Server error' });
    }
};

// POST /api/comments - Tạo comment mới
const createComment = async (req, res) => {
    try {
        const { movieId, type, content, parentId } = req.body;
        const userId = req.user;

        // Get user info
        const user = await User.findById(userId).select('name avatar');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // If it's a reply, check if parent comment exists
        let parentComment = null;
        if (parentId) {
            parentComment = await Comment.findById(parentId);
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
            .populate('userId', 'name avatar')
            .lean();

        if (parentComment && !parentComment.userId.equals(userId)) {
            await createNotificationSafely({
                recipientId: parentComment.userId,
                actorId: userId,
                type: 'comment_replied',
                metadata: {
                    movieId: parseInt(movieId, 10),
                    contentType: type,
                    commentId: comment._id,
                    parentCommentId: parentComment._id,
                    commentPreview: content.trim().substring(0, 160)
                },
                io: req.app.get('io')
            });
        }

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

        const wasLiked = comment.hasUserLiked(userId);

        await comment.toggleLike(userId);

        const isLikedNow = comment.hasUserLiked(userId);

        if (!wasLiked && isLikedNow && !comment.userId.equals(userId)) {
            await createNotificationSafely({
                recipientId: comment.userId,
                actorId: userId,
                type: 'comment_liked',
                metadata: {
                    movieId: comment.movieId,
                    contentType: comment.type,
                    commentId: comment._id,
                    parentCommentId: comment.parentId || undefined,
                    commentPreview: comment.content.substring(0, 160)
                },
                io: req.app.get('io')
            });
        }

        const updatedComment = await Comment.findById(id)
            .populate('userId', 'name avatar')
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
            .populate('userId', 'name avatar')
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
        const deletedCommentIds = [comment._id];
        if (!comment.parentId) {
            // Delete all replies of this top-level comment
            const replies = await Comment.find({ parentId: id }).select('_id').lean();
            deletedCommentIds.push(...replies.map(reply => reply._id));
            await Comment.deleteMany({ parentId: id });
        } else {
            // Pull this reply reference out of parent.replies
            await Comment.findByIdAndUpdate(comment.parentId, { $pull: { replies: comment._id } });
        }

        await Comment.deleteOne({ _id: id });
        await notificationService.deleteNotificationsForComments(deletedCommentIds);

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
            .populate('userId', 'name avatar')
            .sort({ createdAt: 1 })
            .lean();

        const processedReplies = replies.filter(reply => !!reply.userId).map(reply => ({
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
    getCommentThread,
    createComment,
    toggleLike,
    updateComment,
    deleteComment,
    getReplies
};
