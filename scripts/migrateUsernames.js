require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');
const { generateUniqueUsername } = require('../utils/usernameHelper');

async function migrateUsernames() {
  try {
    const mongoUri = process.env.MONGODB_URI;
    if (!mongoUri) {
      console.error('MONGODB_URI not found in environment');
      process.exit(1);
    }

    console.log('Connecting to MongoDB...');
    await mongoose.connect(mongoUri);
    console.log('Connected to MongoDB.');

    // Find all users without a username
    const users = await User.find({
      $or: [
        { username: { $exists: false } },
        { username: null },
        { username: '' }
      ]
    });

    console.log(`Found ${users.length} users needing username migration.`);

    for (const user of users) {
      const generatedUsername = await generateUniqueUsername(user.name, user.email, User);
      user.username = generatedUsername;
      await user.save();
      console.log(`Assigned username "${generatedUsername}" to user "${user.name}" (${user._id})`);
    }

    console.log('Migration completed successfully!');
    await mongoose.disconnect();
    process.exit(0);
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  }
}

migrateUsernames();
