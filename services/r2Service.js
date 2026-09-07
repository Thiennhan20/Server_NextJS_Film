const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');

const accountId = process.env.R2_ACCOUNT_ID;
const accessKeyId = process.env.R2_ACCESS_KEY_ID;
const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
const bucketName = process.env.R2_BUCKET_NAME || 'moviesaw-avatars';
const publicUrl = (process.env.R2_PUBLIC_URL || 'https://pub-1467e531e309456995512f4ba47320c6.r2.dev').replace(/\/$/, '');

let r2Client = null;

function getR2Client() {
  if (!r2Client) {
    if (!accountId || !accessKeyId || !secretAccessKey) {
      console.warn('Cloudflare R2 credentials are not fully configured in environment variables.');
      return null;
    }

    r2Client = new S3Client({
      region: 'auto',
      endpoint: `https://${accountId}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId,
        secretAccessKey,
      },
    });
  }
  return r2Client;
}

/**
 * Upload an image buffer (WebP) to Cloudflare R2
 * @param {Buffer} buffer - Image binary buffer
 * @param {string} userId - User ID or identifier for naming
 * @param {string} extension - File extension (default: 'webp')
 * @param {string} contentType - MIME type (default: 'image/webp')
 * @returns {Promise<string>} - Public CDN URL of uploaded image
 */
async function uploadAvatar(buffer, userId, extension = 'webp', contentType = 'image/webp') {
  const client = getR2Client();
  if (!client) {
    throw new Error('R2 storage client is not configured.');
  }

  const sanitizedUserId = String(userId || 'user').replace(/[^a-zA-Z0-9_-]/g, '');
  const key = `avatars/${sanitizedUserId}_${Date.now()}.${extension}`;

  const command = new PutObjectCommand({
    Bucket: bucketName,
    Key: key,
    Body: buffer,
    ContentType: contentType,
    CacheControl: 'public, max-age=31536000, immutable',
  });

  await client.send(command);

  const fileUrl = `${publicUrl}/${key}`;
  console.log(`[R2] Avatar uploaded successfully: ${fileUrl} (${(buffer.length / 1024).toFixed(1)} KB)`);
  return fileUrl;
}

/**
 * Delete an old avatar from Cloudflare R2
 * @param {string} avatarUrl - URL of avatar to delete
 */
async function deleteAvatar(avatarUrl) {
  if (!avatarUrl || typeof avatarUrl !== 'string') return;

  const client = getR2Client();
  if (!client) return;

  try {
    if (avatarUrl.startsWith(publicUrl)) {
      const key = avatarUrl.replace(`${publicUrl}/`, '');
      if (key && key.startsWith('avatars/')) {
        await client.send(
          new DeleteObjectCommand({
            Bucket: bucketName,
            Key: key,
          })
        );
        console.log(`[R2] Old avatar deleted from R2: ${key}`);
      }
    }
  } catch (err) {
    console.warn('[R2] Warning: Could not delete old avatar from R2:', err.message);
  }
}

/**
 * Check if R2 is configured and ready
 */
function isR2Configured() {
  return Boolean(accountId && accessKeyId && secretAccessKey);
}

module.exports = {
  uploadAvatar,
  deleteAvatar,
  isR2Configured,
  publicUrl,
  bucketName,
};
