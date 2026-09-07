/**
 * Migration Script: Migrate all Base64 avatars in MongoDB to Cloudflare R2
 * Run: node scripts/migrateAvatarsToR2.js
 */

require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');
const { optimizeAvatarToBuffer, base64ToBuffer } = require('../utils/avatarOptimizer');
const { uploadAvatar, isR2Configured } = require('../services/r2Service');

async function migrateAvatars() {
  if (!isR2Configured()) {
    console.error('[Error] Cloudflare R2 is not fully configured in environment variables.');
    process.exit(1);
  }

  const mongoUri = process.env.MONGODB_URI;
  if (!mongoUri) {
    console.error('[Error] MONGODB_URI is not set in .env');
    process.exit(1);
  }

  console.log('[Migration] Connecting to MongoDB...');
  await mongoose.connect(mongoUri);
  console.log('[Migration] Connected to MongoDB successfully.');

  try {
    // Find users with base64 avatars
    const users = await User.find({
      $or: [
        { avatar: { $regex: '^data:image/' } },
        { originalAvatar: { $regex: '^data:image/' } }
      ]
    });

    console.log(`[Migration] Found ${users.length} users with Base64 avatars.`);

    let successCount = 0;
    let failCount = 0;

    for (let i = 0; i < users.length; i++) {
      const user = users[i];
      console.log(`\n[${i + 1}/${users.length}] Processing user: ${user.name} (${user.email || user._id})`);

      let updated = false;
      const wasSame = user.avatar && user.originalAvatar && user.avatar === user.originalAvatar;

      // 1. Process avatar
      if (user.avatar && user.avatar.startsWith('data:image/')) {
        try {
          const buf = base64ToBuffer(user.avatar);
          const webpBuf = await optimizeAvatarToBuffer(buf);
          const r2Url = await uploadAvatar(webpBuf, user._id);
          user.avatar = r2Url;
          updated = true;
          console.log(`  -> Avatar migrated to R2: ${r2Url}`);
        } catch (err) {
          console.error(`  -> Failed to migrate avatar for ${user.email}:`, err.message);
          failCount++;
        }
      }

      // 2. Process originalAvatar
      if (user.originalAvatar && user.originalAvatar.startsWith('data:image/')) {
        try {
          if (wasSame && user.avatar && user.avatar.startsWith('http')) {
            // If avatar and originalAvatar were identical, reuse the uploaded URL
            user.originalAvatar = user.avatar;
            updated = true;
            console.log(`  -> Reused R2 URL for originalAvatar: ${user.originalAvatar}`);
          } else {
            const buf = base64ToBuffer(user.originalAvatar);
            const webpBuf = await optimizeAvatarToBuffer(buf);
            const r2Url = await uploadAvatar(webpBuf, `${user._id}_orig`);
            user.originalAvatar = r2Url;
            updated = true;
            console.log(`  -> OriginalAvatar migrated to R2: ${r2Url}`);
          }
        } catch (err) {
          console.error(`  -> Failed to migrate originalAvatar for ${user.email}:`, err.message);
          failCount++;
        }
      }

      if (updated) {
        await user.save();
        successCount++;
      }
    }

    console.log('\n==========================================');
    console.log(`[Migration Complete]`);
    console.log(`  - Total users checked: ${users.length}`);
    console.log(`  - Successfully migrated: ${successCount}`);
    console.log(`  - Errors: ${failCount}`);
    console.log('==========================================');
  } catch (err) {
    console.error('[Migration Error]:', err);
  } finally {
    await mongoose.disconnect();
    console.log('[Migration] Disconnected from MongoDB.');
  }
}

migrateAvatars();
