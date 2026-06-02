const sharp = require('sharp');

/**
 * Optimize avatar image
 * - Convert to WebP format
 * - Resize to 200x200 (smaller for faster load)
 * - Compress to ~30KB (much smaller)
 * @param {Buffer} imageBuffer - Input image buffer
 * @returns {Promise<string>} - Base64 WebP string
 */
async function optimizeAvatar(imageBuffer) {
  try {
    const optimized = await sharp(imageBuffer)
      .resize(500, 500, {
        fit: 'cover',
        position: 'center'
      })
      .webp({
        quality: 80, // Upgraded quality for sharp full-screen previews
        effort: 4 // Faster compression
      })
      .toBuffer();

    // Convert to base64
    const base64 = `data:image/webp;base64,${optimized.toString('base64')}`;
    
    console.log('Avatar optimization:', {
      originalSize: `${(imageBuffer.length / 1024).toFixed(2)} KB`,
      optimizedSize: `${(optimized.length / 1024).toFixed(2)} KB`,
      reduction: `${(((imageBuffer.length - optimized.length) / imageBuffer.length) * 100).toFixed(1)}%`,
      base64Length: base64.length
    });

    return base64;
  } catch (error) {
    console.error('Avatar optimization error:', error);
    throw new Error('Failed to optimize avatar');
  }
}

/**
 * Convert base64 to buffer
 * @param {string} base64String - Base64 string (with or without data URI prefix)
 * @returns {Buffer} - Image buffer
 */
function base64ToBuffer(base64String) {
  // Remove data URI prefix if present
  const base64Data = base64String.replace(/^data:image\/\w+;base64,/, '');
  return Buffer.from(base64Data, 'base64');
}

/**
 * Validate image buffer
 * @param {Buffer} buffer - Image buffer
 * @returns {Promise<boolean>} - True if valid image
 */
async function validateImage(buffer) {
  try {
    const metadata = await sharp(buffer).metadata();
    return metadata.width > 0 && metadata.height > 0;
  } catch {
    return false;
  }
}

module.exports = {
  optimizeAvatar,
  base64ToBuffer,
  validateImage
};
