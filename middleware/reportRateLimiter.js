const { RateLimiterMemory } = require('rate-limiter-flexible');

// Rate limiter: 8 reports per 10 minutes (600 seconds) per authenticated user (or IP fallback)
const reportLimiter = new RateLimiterMemory({
  points: 8,
  duration: 600,
});

const limitCommentReports = async (req, res, next) => {
  try {
    const key = req.user ? `user:${String(req.user)}` : `ip:${req.ip || 'unknown'}`;
    await reportLimiter.consume(key);
    return next();
  } catch (rejRes) {
    const retrySecs = Math.ceil((rejRes?.msBeforeNext || 60000) / 1000) || 60;
    const mins = Math.max(1, Math.ceil(retrySecs / 60));
    const isVi = (req.headers['accept-language'] || '').toLowerCase().includes('vi');

    res.set('Retry-After', String(retrySecs));
    return res.status(429).json({
      success: false,
      code: 'RATE_LIMITED',
      message: isVi
        ? `Bạn đang gửi báo cáo quá nhanh. Vui lòng thử lại sau ${mins} phút.`
        : `You are submitting reports too quickly. Please try again in ${mins} minute(s).`,
      retryAfter: retrySecs,
    });
  }
};

module.exports = limitCommentReports;

