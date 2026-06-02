const { RateLimiterMemory } = require('rate-limiter-flexible');

// Rate limiter: 5 requests per 10 minutes (600 seconds) per USER
const avatarRateLimiter = new RateLimiterMemory({
    points: 5,
    duration: 600,
});

const limitAvatarUpload = async (req, res, next) => {
    try {
        const { avatar } = req.body;
        
        // Chỉ giới hạn tần suất khi người dùng thực sự tải lên một ảnh đại diện tùy biến mới
        // (Bỏ qua khi họ chỉ cập nhật Tên, Xóa ảnh đại diện hoặc Khôi phục về ảnh gốc của Google)
        if (avatar !== undefined && avatar !== '' && avatar.startsWith('data:image/')) {
            const key = req.user ? req.user.toString() : req.ip;
            
            try {
                await avatarRateLimiter.consume(key);
                next();
            } catch (rejRes) {
                const secs = Math.ceil(rejRes.msBeforeNext / 1000);
                const mins = Math.ceil(secs / 60);
                
                const lang = (req.headers['accept-language'] || '').toLowerCase();
                const isVi = lang.includes('vi');
                
                return res.status(429).json({ 
                    message: isVi
                        ? `Bạn đã đổi ảnh đại diện quá nhanh. Vui lòng thử lại sau ${mins} phút.`
                        : `Too many avatar changes. Please try again after ${mins} minutes.`,
                    retryAfter: secs
                });
            }
        } else {
            next();
        }
    } catch (error) {
        next(error);
    }
};

module.exports = limitAvatarUpload;
