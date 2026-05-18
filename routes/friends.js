const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const friendController = require('../controllers/friendController');

// GET /api/friends - Lấy danh sách bạn bè, lời mời nhận, lời mời gửi
router.get('/', auth, friendController.getFriendsData);

// POST /api/friends/request/:id - Gửi lời mời kết bạn
router.post('/request/:id', auth, friendController.sendRequest);

// POST /api/friends/accept/:id - Chấp nhận kết bạn
router.post('/accept/:id', auth, friendController.acceptRequest);

// POST /api/friends/reject/:id - Từ chối kết bạn
router.post('/reject/:id', auth, friendController.rejectRequest);

// POST /api/friends/cancel/:id - Hủy lời mời kết bạn đã gửi
router.post('/cancel/:id', auth, friendController.cancelRequest);

// DELETE /api/friends/:id - Hủy kết bạn
router.delete('/:id', auth, friendController.removeFriend);

module.exports = router;
