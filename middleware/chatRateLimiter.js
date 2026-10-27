const { RateLimiterMemory } = require('rate-limiter-flexible');

// Giới hạn tần suất: Tối đa 30 request chat/stream mỗi phút (60 giây) cho mỗi địa chỉ IP
const chatLimiter = new RateLimiterMemory({
    points: 30,
    duration: 60,
});

const limitChatRequests = async (req, res, next) => {
    try {
        const clientIp = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
        await chatLimiter.consume(clientIp);
        next();
    } catch (rejRes) {
        const retrySecs = Math.ceil(rejRes.msBeforeNext / 1000) || 5;
        res.set('Retry-After', String(retrySecs));
        return res.status(429).json({
            error: `Bạn đang nhắn tin quá nhanh. Vui lòng chờ ${retrySecs} giây rồi thử lại nhé! 🍿`,
            retryAfter: retrySecs
        });
    }
};

module.exports = limitChatRequests;
