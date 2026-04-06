const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const auth = require('../middleware/auth');
const optionalAuth = require('../middleware/optionalAuth');
const commentController = require('../controllers/commentController');

// GET /api/comments/top - Lấy top comments (most liked or most replied) for homepage
router.get('/top', optionalAuth, commentController.getTopComments);

// GET /api/comments/recent - Lấy recent comments (newest across all movies) for homepage
router.get('/recent', optionalAuth, commentController.getRecentComments);

// GET /api/comments/user/me - Lấy comments của mình
router.get('/user/me', auth, commentController.getUserComments);

// GET /api/comments/:movieId/:type - Lấy comments với phân trang, sort DB-side và batched replies
router.get('/:movieId/:type', optionalAuth, commentController.getCommentsByMovie);

// POST /api/comments - Tạo comment mới
router.post('/', [
  auth,
  body('movieId').isNumeric().withMessage('Movie ID must be a number'),
  body('type').isIn(['movie', 'tvshow']).withMessage('Type must be movie or tvshow'),
  body('content').isLength({ min: 1, max: 500 }).withMessage('Content must be between 1 and 500 characters'),
  body('parentId').optional().isMongoId().withMessage('Parent ID must be a valid MongoDB ObjectId')
], commentController.validateRequest, commentController.createComment);

// PUT /api/comments/:id/like - Toggle like cho comment
router.put('/:id/like', auth, commentController.toggleLike);

// PUT /api/comments/:id - Cập nhật nội dung comment
router.put(
  '/:id',
  [
    auth,
    body('content')
      .isLength({ min: 1, max: 500 })
      .withMessage('Content must be between 1 and 500 characters'),
  ],
  commentController.validateRequest,
  commentController.updateComment
);

// DELETE /api/comments/:id - Xóa comment (soft delete)
router.delete('/:id', auth, commentController.deleteComment);

// GET /api/comments/:id/replies - Lấy replies của một comment
router.get('/:id/replies', optionalAuth, commentController.getReplies);

module.exports = router;
