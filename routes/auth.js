const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const auth = require('../middleware/auth');
const optionalAuth = require('../middleware/optionalAuth');
const authController = require('../controllers/authController');

// Register route
router.post('/register', [
  body('name').notEmpty().withMessage('Please enter your name'),
  body('email').isEmail().withMessage('Please enter a valid email'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
], authController.register);

// Login route
router.post('/login', [
  body('email').isEmail().withMessage('Please enter a valid email'),
  body('password').exists().withMessage('Password is required'),
], authController.login);

// Google login / link route (server verifies Google ID token or access token)
router.post('/google-login', [
  body().custom((value, { req }) => {
    if (!req.body.credential && !req.body.accessToken) {
      throw new Error('Google credential or access token is required');
    }
    return true;
  }),
], authController.googleLogin);

// ===== Mobile App Google OAuth (server-side flow) =====
// Bước 1: App mở browser → Server redirect tới Google OAuth
router.get('/google/mobile', authController.googleMobileInit);
// Bước 2: Google redirect về server → Server xử lý → Redirect về app bằng deep link
router.get('/google/mobile-callback', authController.googleMobileCallback);

// Logout route
router.post('/logout', auth, authController.logout);

// Protected route - Get profile
router.get('/profile', auth, authController.getProfile);

// Public profile
router.get('/profile/:id', optionalAuth, authController.getPublicProfile);

// Update user profile (avatar, name)
router.put('/profile', auth, authController.updateProfile);

// Xác thực email
router.get('/verify-email', authController.verifyEmail);

// API kiểm tra trạng thái xác thực email
router.get('/check-email-verified', authController.checkEmailVerified);

// Forgot password - request reset link
router.post(
  '/forgot-password',
  [body('email').isEmail().withMessage('Please enter a valid email')],
  authController.forgotPassword
);

// Reset password using token from email
router.post(
  '/reset-password',
  [
    body('email').isEmail().withMessage('Please enter a valid email'),
    body('token').notEmpty().withMessage('Token is required'),
    body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  ],
  authController.resetPassword
);

// Check reset token validity (used by reset-password page)
router.get('/check-reset-token', authController.checkResetToken);

// ================= WATCHLIST ENDPOINTS =================
// Thêm phim vào watchlist
router.post('/watchlist', auth, authController.addToWatchlist);

// Xóa phim khỏi watchlist
router.delete('/watchlist', auth, authController.removeFromWatchlist);

// Lấy toàn bộ watchlist của user
router.get('/watchlist', auth, authController.getWatchlist);

// ================= ADMIN API ENDPOINTS =================
// Lấy tất cả users (cho Django Admin)
router.get('/users', authController.getUsers);

// Lấy user theo ID
router.get('/users/:id', authController.getUserById);

// Cập nhật user theo ID
router.put('/users/:id', authController.updateUser);

// Xóa user theo ID
router.delete('/users/:id', authController.deleteUser);

module.exports = router;
