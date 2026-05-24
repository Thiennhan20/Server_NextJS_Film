const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const WatchProgress = require('../models/WatchProgress');
const BlacklistedToken = require('../models/BlacklistedToken');
const { optimizeAvatar, base64ToBuffer, validateImage } = require('../utils/avatarOptimizer');
const authService = require('../services/authService');
const PasswordResetToken = require('../models/PasswordResetToken');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

// Middleware to validate request
const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

const rateLimitMiddleware = (req, res, next) => {
    authService.consumeRateLimit(req.ip)
        .then(() => next())
        .catch(() => {
            res.status(429).json({ message: 'Too many requests. Please try again later.' });
        });
};

// ======= Forgot password / Reset password =======

const forgotPassword = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: 'Invalid email address' });
        }

        const rawEmail = req.body.email;
        const email = typeof rawEmail === 'string' ? rawEmail.toLowerCase().trim() : '';
        const ipAddress = req.ip || req.headers['x-forwarded-for'] || '';

        if (!email) {
            return res.status(400).json({ message: 'Invalid email address' });
        }

        // Rate limit: max 3 reset requests per hour per email
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        const requestCount = await PasswordResetToken.countDocuments({
            email,
            createdAt: { $gte: oneHourAgo },
        });

        if (requestCount >= 3) {
            return res.status(429).json({ message: 'Please wait before trying again' });
        }

        // Look up user with email auth type
        const user = await User.findOne({
            email,
            $or: [
                { authType: 'email' },
                { authType: { $exists: false } }, // legacy
            ],
        });

        // Always create a token document for consistent timing and rate limit,
        // but only link to a user if one exists and uses email auth.
        const token = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        await PasswordResetToken.create({
            user: user ? user._id : null,
            email,
            tokenHash,
            expiresAt,
            ipAddress: String(ipAddress),
        });

        if (user && (user.authType === 'email' || !user.authType)) {
            const resetUrl = `${process.env.CLIENT_URL || 'http://localhost:3000'}/reset-password?token=${token}&email=${encodeURIComponent(email)}`;
            await authService.sendPasswordResetEmail(user.email, user.name || user.email, resetUrl);
        }

        // Always respond with generic message to avoid email enumeration
        return res.json({
            message: 'If email exists, reset link has been sent',
        });
    } catch (error) {
        console.error('Forgot password error:', error);
        return res.status(500).json({ message: 'Server error' });
    }
};

const resetPassword = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: 'Invalid request' });
        }

        const { email: rawEmail, token, newPassword, confirmPassword } = req.body;
        const email = typeof rawEmail === 'string' ? rawEmail.toLowerCase().trim() : '';

        if (!email) {
            return res.status(400).json({ message: 'Invalid email address' });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: 'Password confirmation does not match' });
        }

        // Password complexity: at least 8 chars, upper, lower, digit, special
        const hasMinLength = newPassword.length >= 8;
        const hasUpper = /[A-Z]/.test(newPassword);
        const hasLower = /[a-z]/.test(newPassword);
        const hasDigit = /[0-9]/.test(newPassword);
        const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(newPassword);

        if (!(hasMinLength && hasUpper && hasLower && hasDigit && hasSpecial)) {
            return res.status(400).json({ message: 'Password does not meet complexity requirements' });
        }

        const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
        const resetRecord = await PasswordResetToken.findOne({ email, tokenHash });

        if (!resetRecord) {
            return res.status(400).json({ message: 'Link is invalid or expired. Please try again.' });
        }

        const now = new Date();

        if (resetRecord.usedAt) {
            return res.status(400).json({ message: 'Link has already been used.' });
        }

        if (resetRecord.expiresAt <= now) {
            return res.status(400).json({ message: 'Link is invalid or expired. Please try again.' });
        }

        if (resetRecord.attempts >= 5) {
            return res.status(400).json({ message: 'Too many attempts. Please request a new link.' });
        }

        // Load user
        const user = await User.findOne({
            _id: resetRecord.user,
            email,
            $or: [
                { authType: 'email' },
                { authType: { $exists: false } },
            ],
        });

        if (!user) {
            // Increment attempts to prevent brute forcing tokens
            resetRecord.attempts += 1;
            await resetRecord.save();
            return res.status(400).json({ message: 'Link is invalid or expired. Please try again.' });
        }

        // Check new password is not same as old
        if (user.password) {
            const isSame = await bcrypt.compare(newPassword, user.password);
            if (isSame) {
                return res.status(400).json({ message: 'New password must be different from the old password.' });
            }
        }

        // Update password (pre-save hook will hash and update passwordChangedAt)
        user.password = newPassword;
        await user.save();

        resetRecord.usedAt = now;
        await resetRecord.save();

        // Optionally, notify user by email that password was changed
        // Reuse password reset email channel with a short notice
        try {
            await authService.sendPasswordResetEmail(
                user.email,
                user.name || user.email,
                `${process.env.CLIENT_URL || 'http://localhost:3000'}/login`
            );
        } catch {
            // Non-fatal if notification email fails
        }

        return res.json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Reset password error:', error);
        return res.status(500).json({ message: 'Server error' });
    }
};

// Validate reset password token without changing password (for UX on reset page)
const checkResetToken = async (req, res) => {
    try {
        const { email: rawEmail, token } = req.query;
        const email = typeof rawEmail === 'string' ? rawEmail.toLowerCase().trim() : '';

        if (!email || !token || typeof token !== 'string') {
            return res.status(400).json({ message: 'Link is invalid or expired.' });
        }

        const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
        const resetRecord = await PasswordResetToken.findOne({ email, tokenHash });

        if (!resetRecord) {
            return res.status(400).json({ message: 'Link is invalid or expired. Please try again.' });
        }

        const now = new Date();

        if (resetRecord.usedAt) {
            return res.status(400).json({ message: 'Link has already been used.' });
        }

        if (resetRecord.expiresAt <= now) {
            return res.status(400).json({ message: 'Link is invalid or expired. Please try again.' });
        }

        if (resetRecord.attempts >= 5) {
            return res.status(400).json({ message: 'Too many attempts. Please request a new link.' });
        }

        return res.json({ valid: true });
    } catch (error) {
        console.error('Check reset token error:', error);
        return res.status(500).json({ message: 'Server error' });
    }
};

// Register
const register = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { name, email, password } = req.body;

        // Check for existing email user (ONLY email auth type)
        let user = await User.findOne({
            email,
            $or: [
                { authType: 'email' },
                { authType: { $exists: false } } // Legacy users
            ]
        });

        if (user) {
            // If legacy user, update to email auth type
            if (!user.authType) {
                user.authType = 'email';
                await user.save();
            }

            // Email user already exists - check verification status
            if (!user.isEmailVerified) {
                // Gửi lại email xác thực
                const emailVerificationToken = authService.generateVerificationToken();
                user.emailVerificationToken = emailVerificationToken;
                await user.save();
                const verifyUrl = authService.buildVerifyUrl(emailVerificationToken, email);

                await authService.sendVerificationEmail(
                    email, name, verifyUrl,
                    'Entertainment World Account Email Verification Resend'
                );
                return res.status(200).json({
                    message: 'This email has already been registered but not yet verified. A verification email has been resent, please check your inbox.'
                });

            }
            // Email user already exists and verified - return error
            return res.status(400).json({ message: 'User already exists' });
        }

        // No email user found - REGISTER (create new)
        const emailVerificationToken = authService.generateVerificationToken();
        user = new User({
            name,
            email,
            password,
            authType: 'email',
            emailVerificationToken,
            isEmailVerified: false
        });
        await user.save();

        // Gửi email xác thực bằng Brevo (HTTPS)
        const verifyUrl = authService.buildVerifyUrl(emailVerificationToken, email);

        await authService.sendVerificationEmail(
            email, name, verifyUrl,
            'Entertainment World Account Email Verification'
        );

        return res.status(201).json({
            message: 'Registration successful! Please check your email to verify your account.',
        });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Login
const login = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { email, password } = req.body;

        // Check for existing email user (including legacy users without authType)
        const user = await User.findOne({
            email,
            $or: [
                { authType: 'email' },
                { authType: { $exists: false } } // Legacy users
            ]
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // If legacy user, update to email auth type
        if (!user.authType) {
            user.authType = 'email';
            await user.save();
        }
        if (!user.isEmailVerified) {
            return res.status(403).json({ message: 'Account email not verified, please check your email to verify.' });
        }
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        // Create JWT token
        const token = authService.createToken(user._id);

        res.json({
            token,
            user: authService.formatUserResponse(user)
        });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Google login / link route (server verifies Google ID token or access token from mobile)
const googleLogin = async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { credential, accessToken, userInfo: clientUserInfo } = req.body;

        let email, sub, name, avatar, email_verified;

        if (credential) {
            // Flow 1: ID Token (from website) — verify with Google Auth Library
            const { OAuth2Client } = require('google-auth-library');
            const allowedClientIds = [
                process.env.GOOGLE_CLIENT_ID,
                process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID,
                process.env.GOOGLE_CLIENT_ID_IOS,
                process.env.GOOGLE_CLIENT_ID_ANDROID,
            ].filter(Boolean);
            
            const primaryClientId = allowedClientIds[0];
            const client = new OAuth2Client(primaryClientId);
            const ticket = await client.verifyIdToken({ 
                idToken: credential, 
                audience: allowedClientIds 
            });
            const payload = ticket.getPayload();
            if (!payload) return res.status(401).json({ message: 'Invalid Google token' });

            email = payload.email;
            sub = payload.sub;
            name = payload.name;
            avatar = payload.picture;
            email_verified = payload.email_verified;
        } else if (accessToken) {
            // Flow 2: Access Token (from Expo Go mobile app) — verify with Google UserInfo API
            try {
                const axios = require('axios');
                const googleRes = await axios.get('https://www.googleapis.com/userinfo/v2/me', {
                    headers: { Authorization: `Bearer ${accessToken}` },
                });
                
                const googleUserInfo = googleRes.data;
                
                email = googleUserInfo.email;
                sub = googleUserInfo.id;
                name = googleUserInfo.name;
                avatar = googleUserInfo.picture;
                email_verified = googleUserInfo.verified_email;
            } catch (fetchError) {
                // Fallback: if fetch fails but client sent userInfo, use it cautiously
                if (clientUserInfo && clientUserInfo.email && clientUserInfo.id) {
                    email = clientUserInfo.email;
                    sub = clientUserInfo.id;
                    name = clientUserInfo.name;
                    avatar = clientUserInfo.picture;
                    email_verified = clientUserInfo.verified_email;
                } else {
                    return res.status(401).json({ message: 'Could not verify Google account' });
                }
            }
        } else {
            return res.status(400).json({ message: 'Google credential or access token is required' });
        }

        if (!email) {
            return res.status(401).json({ message: 'Could not retrieve email from Google account' });
        }

        // Check if Google user already exists (email + authType: 'google')
        let user = await User.findOne({ email, authType: 'google' });

        if (user) {
            // Google user exists - LOGIN

            // Update user info if needed
            if (name && user.name !== name) {
                user.name = name;
            }

            // Cập nhật avatar và originalAvatar nếu cần
            if (avatar) {
                // Nếu chưa có originalAvatar hoặc vẫn là URL (chưa optimize)
                if (!user.originalAvatar || user.originalAvatar === '' || user.originalAvatar.startsWith('http')) {
                    // Download và optimize avatar
                    const optimizedAvatar = await authService.downloadAndOptimizeAvatar(avatar);
                    user.originalAvatar = optimizedAvatar;
                }

                // Chỉ cập nhật avatar nếu user chưa upload custom avatar
                if (!user.avatar || user.avatar === '' || user.avatar.startsWith('http')) {
                    user.avatar = user.originalAvatar; // Use cached optimized version
                }
            }
            await user.save();

            const token = authService.createToken(user._id);
            return res.json({
                token,
                user: authService.formatUserResponse(user)
            });
        }

        // Google user doesn't exist - REGISTER (create new)
        // Download and optimize avatar first
        const optimizedAvatar = avatar ? await authService.downloadAndOptimizeAvatar(avatar) : '';

        user = await User.findOneAndUpdate(
            { email, authType: 'google' },
            {
                name: name || email,
                email,
                authType: 'google',
                providerId: sub,
                avatar: optimizedAvatar,
                originalAvatar: optimizedAvatar, // Lưu avatar đã optimize
                isEmailVerified: !!email_verified,
                emailVerificationToken: ''
            },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        const token = authService.createToken(user._id);
        return res.status(201).json({
            token,
            user: authService.formatUserResponse(user)
        });
    } catch {
        res.status(500).json({ message: 'Server error' });
    }
};


// Logout
const logout = async (req, res) => {
    try {
        const token = req.token; // Token được đính kèm vào req bởi middleware auth
        const decoded = jwt.decode(token); // Giải mã token để lấy thông tin expiresAt

        if (!decoded || !decoded.exp) {
            return res.status(400).json({ message: 'Invalid token provided' });
        }

        const expiresAt = new Date(decoded.exp * 1000); // Chuyển đổi timestamp Unix sang Date object

        const blacklistedToken = new BlacklistedToken({
            token,
            expiresAt,
        });

        await blacklistedToken.save();

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Get profile
const getProfile = async (req, res) => {
    try {
        // req.user chứa userId từ token đã được middleware auth đính kèm
        const user = await User.findById(req.user).select('-password -emailVerificationToken');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({
            user: authService.formatUserResponse(user)
        });
    } catch {
        res.status(500).json({ message: 'Server error' });
    }
};

// Get public profile
const getPublicProfile = async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('name avatar originalAvatar createdAt friends');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const viewerId = req.user ? req.user.toString() : null;
        const isOwner = viewerId && user._id.toString() === viewerId;
        const isFriend = viewerId && user.friends?.some(friendId => friendId.toString() === viewerId);
        const canViewRecentlyWatched = isOwner || isFriend;

        const recentlyWatched = canViewRecentlyWatched
            ? await WatchProgress.aggregate([
                { $match: { userId: user._id } },
                { $sort: { lastWatched: -1 } },
                {
                    $group: {
                        _id: "$contentId",
                        doc: { $first: "$$ROOT" }
                    }
                },
                { $replaceRoot: { newRoot: "$doc" } },
                { $sort: { lastWatched: -1 } },
                { $limit: 20 },
                { $project: { contentId: 1, isTVShow: 1, title: 1, poster: 1 } }
            ])
            : [];

        res.json({
            user: {
                _id: user._id,
                name: user.name,
                avatar: user.avatar,
                originalAvatar: user.originalAvatar,
                createdAt: user.createdAt,
            },
            recentlyWatched
        });
    } catch {
        res.status(500).json({ message: 'Server error' });
    }
};

// Update profile
const updateProfile = async (req, res) => {
    try {
        const { name, avatar } = req.body;

        const user = await User.findById(req.user);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Cập nhật thông tin
        if (name !== undefined) user.name = name;
        if (avatar !== undefined) {
            // Nếu avatar là empty string, khôi phục originalAvatar (nếu có)
            if (avatar === '') {
                if (user.originalAvatar && user.originalAvatar !== '') {
                    user.avatar = user.originalAvatar;
                } else {
                    user.avatar = '';
                }
            }
            // Nếu avatar là data URL, optimize nó
            else if (avatar.startsWith('data:image/')) {
                try {
                    const imageBuffer = base64ToBuffer(avatar);

                    // Validate image
                    const isValid = await validateImage(imageBuffer);
                    if (!isValid) {
                        return res.status(400).json({ message: 'Invalid image format' });
                    }

                    // Optimize to WebP
                    const optimizedAvatar = await optimizeAvatar(imageBuffer);
                    user.avatar = optimizedAvatar;
                } catch {
                    return res.status(400).json({ message: 'Failed to process avatar image' });
                }
            }
            // Nếu avatar là HTTP(S) URL, giữ nguyên
            else if (avatar.startsWith('http://') || avatar.startsWith('https://')) {
                user.avatar = avatar;
            } else {
                return res.status(400).json({ message: 'Invalid avatar format' });
            }
        }

        await user.save();

        // Trả về user đã cập nhật (không bao gồm password)
        const updatedUser = await User.findById(req.user).select('-password -emailVerificationToken');

        res.json({
            user: authService.formatUserResponse(updatedUser)
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
};

// Verify email
const verifyEmail = async (req, res) => {
    const { token, email } = req.query;
    if (!token || !email) {
        return res.status(400).json({ message: 'Missing token or email' });
    }
    const user = await User.findOne({
        email,
        $or: [
            { authType: 'email' },
            { authType: { $exists: false } } // Legacy users
        ]
    });
    if (!user) {
        return res.status(400).json({ message: 'Invalid or expired token' });
    }

    // If legacy user, update to email auth type
    if (!user.authType) {
        user.authType = 'email';
        await user.save();
    }
    // Nếu đã xác thực rồi, báo lỗi
    if (user.isEmailVerified) {
        return res.status(400).json({ message: 'Account already verified or link expired.' });
    }
    // Nếu chưa xác thực, kiểm tra token
    if (user.emailVerificationToken !== token) {
        return res.status(400).json({ message: 'Invalid or expired token' });
    }
    user.isEmailVerified = true;
    user.emailVerificationToken = '';
    await user.save();
    return res.json({
        message: 'Email verification successful! You can now login.'
    });
};

// Check email verified
const checkEmailVerified = async (req, res) => {
    const { email } = req.query;
    if (!email) {
        return res.status(400).json({ message: 'Missing email' });
    }
    const user = await User.findOne({
        email,
        $or: [
            { authType: 'email' },
            { authType: { $exists: false } } // Legacy users
        ]
    });
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    return res.json({ isEmailVerified: !!user.isEmailVerified });
};

// ================= WATCHLIST ENDPOINTS =================
// Add to watchlist
const addToWatchlist = async (req, res) => {
    try {
        const { id, title, poster_path, type } = req.body;
        if (!id || !title || !poster_path) {
            return res.status(400).json({ message: 'Missing movie information' });
        }
        const user = await User.findById(req.user);
        if (!user) return res.status(404).json({ message: 'User not found' });
        // Kiểm tra trùng bằng cách convert cả 2 về String để phòng hờ Mobile App gửi string / Web App gửi number
        if (user.watchlist.some(m => String(m.id) === String(id))) {
            return res.status(400).json({ message: 'Movie already in watchlist' });
        }
        user.watchlist.push({ id: Number(id) || id, title, poster_path, type: type || 'movie' });
        await user.save();
        res.json({ message: 'Added to watchlist', watchlist: user.watchlist });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Remove from watchlist
const removeFromWatchlist = async (req, res) => {
    try {
        const { id } = req.body;
        if (!id) return res.status(400).json({ message: 'Missing movie id' });
        const user = await User.findById(req.user);
        if (!user) return res.status(404).json({ message: 'User not found' });
        user.watchlist = user.watchlist.filter(m => String(m.id) !== String(id));
        await user.save();
        res.json({ message: 'Removed from watchlist', watchlist: user.watchlist });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Get watchlist
const getWatchlist = async (req, res) => {
    try {
        const user = await User.findById(req.user);
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json({ watchlist: user.watchlist });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

// ================= ADMIN API ENDPOINTS =================
// Get all users
const getUsers = async (req, res) => {
    try {
        const users = await User.find({}).select('-password -emailVerificationToken');
        res.json(users);
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Get user by ID
const getUserById = async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password -emailVerificationToken');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Update user by ID
const updateUser = async (req, res) => {
    try {
        const { name, email, avatar, isEmailVerified, watchlist } = req.body;

        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Cập nhật thông tin
        if (name) user.name = name;
        if (email) user.email = email;
        if (avatar !== undefined) user.avatar = avatar;
        if (isEmailVerified !== undefined) user.isEmailVerified = isEmailVerified;
        if (watchlist !== undefined) user.watchlist = watchlist;

        await user.save();

        // Trả về user đã cập nhật (không bao gồm password)
        const updatedUser = await User.findById(req.params.id).select('-password -emailVerificationToken');
        res.json(updatedUser);
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Delete user by ID
const deleteUser = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'User deleted successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

// ===== Mobile App Google OAuth (server-side flow) =====
// Bước 1: Redirect trình duyệt tới Google OAuth
const googleMobileInit = (req, res) => {
    try {
        const clientId = process.env.GOOGLE_CLIENT_ID || process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;
        if (!clientId) {
            return res.status(500).send('Google Client ID not configured');
        }

        // GOOGLE_REDIRECT_BASE_URL cho phép cấu hình redirect URI chính xác
        // Local dev: http://localhost:3001 (Google chấp nhận localhost)
        // Production: https://server-nextjs-firm.onrender.com
        const baseUrl = process.env.GOOGLE_REDIRECT_BASE_URL || 
            `${req.headers['x-forwarded-proto'] || req.protocol}://${req.headers['x-forwarded-host'] || req.get('host')}`;
        const redirectUri = `${baseUrl}/api/auth/google/mobile-callback`;

        console.log('Google OAuth redirect URI:', redirectUri);

        const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' +
            `client_id=${encodeURIComponent(clientId)}&` +
            `redirect_uri=${encodeURIComponent(redirectUri)}&` +
            'response_type=code&' +
            'scope=openid%20profile%20email&' +
            'prompt=select_account';

        res.redirect(authUrl);
    } catch (error) {
        console.error('Google mobile init error:', error);
        res.redirect('ntnmovie://auth?error=init_failed');
    }
};

// Bước 2: Nhận callback từ Google, tạo/tìm user, redirect về app
const googleMobileCallback = async (req, res) => {
    try {
        const { code, error: googleError } = req.query;

        if (googleError || !code) {
            return res.redirect(`ntnmovie://auth?error=${googleError || 'no_code'}`);
        }

        const clientId = process.env.GOOGLE_CLIENT_ID || process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;
        const clientSecret = process.env.GOOGLE_CLIENT_SECRET;

        // Phải dùng cùng redirect URI đã dùng ở bước 1
        const baseUrl = process.env.GOOGLE_REDIRECT_BASE_URL || 
            `${req.headers['x-forwarded-proto'] || req.protocol}://${req.headers['x-forwarded-host'] || req.get('host')}`;
        const redirectUri = `${baseUrl}/api/auth/google/mobile-callback`;

        // Đổi authorization code lấy access token
        const axios = require('axios');
        const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
            code,
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code',
        });

        const { access_token } = tokenResponse.data;

        // Lấy thông tin user từ Google
        const userInfoResponse = await axios.get('https://www.googleapis.com/userinfo/v2/me', {
            headers: { Authorization: `Bearer ${access_token}` },
        });

        const googleUserInfo = userInfoResponse.data;
        const email = googleUserInfo.email;
        const sub = googleUserInfo.id;
        const name = googleUserInfo.name;
        const avatar = googleUserInfo.picture;
        const email_verified = googleUserInfo.verified_email;

        if (!email) {
            return res.redirect('ntnmovie://auth?error=no_email');
        }

        // Tìm hoặc tạo user (logic giống googleLogin)
        let user = await User.findOne({ email, authType: 'google' });

        if (user) {
            // User đã tồn tại — cập nhật info
            if (name && user.name !== name) user.name = name;

            if (avatar) {
                if (!user.originalAvatar || user.originalAvatar === '' || user.originalAvatar.startsWith('http')) {
                    try {
                        const optimizedAvatar = await authService.downloadAndOptimizeAvatar(avatar);
                        user.originalAvatar = optimizedAvatar;
                    } catch { /* ignore optimization errors */ }
                }
                if (!user.avatar || user.avatar === '' || user.avatar.startsWith('http')) {
                    user.avatar = user.originalAvatar || avatar;
                }
            }
            await user.save();
        } else {
            // User mới — tạo account
            let optimizedAvatar = '';
            if (avatar) {
                try {
                    optimizedAvatar = await authService.downloadAndOptimizeAvatar(avatar);
                } catch { optimizedAvatar = ''; }
            }

            user = await User.findOneAndUpdate(
                { email, authType: 'google' },
                {
                    name: name || email,
                    email,
                    authType: 'google',
                    providerId: sub,
                    avatar: optimizedAvatar,
                    originalAvatar: optimizedAvatar,
                    isEmailVerified: !!email_verified,
                    emailVerificationToken: ''
                },
                { upsert: true, new: true, setDefaultsOnInsert: true }
            );
        }

        // Tạo JWT token
        const token = authService.createToken(user._id);

        // Redirect về app bằng deep link
        res.redirect(`ntnmovie://auth?token=${token}`);
    } catch (error) {
        console.error('Google mobile callback error:', error.response?.data || error.message);
        res.redirect('ntnmovie://auth?error=server_error');
    }
};

module.exports = {
    validateRequest,
    rateLimitMiddleware,
    register,
    login,
    googleLogin,
    googleMobileInit,
    googleMobileCallback,

    logout,
    getProfile,
    getPublicProfile,
    updateProfile,
    verifyEmail,
    checkEmailVerified,
    forgotPassword,
    resetPassword,
    checkResetToken,
    addToWatchlist,
    removeFromWatchlist,
    getWatchlist,
    getUsers,
    getUserById,
    updateUser,
    deleteUser
};
