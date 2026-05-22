const mongoose = require('mongoose');

const watchProgressSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  contentId: { type: String, required: true }, // movieId or tv show id as string
  isTVShow: { type: Boolean, default: false },
  season: { type: Number, default: null },
  episode: { type: Number, default: null },
  server: { type: String, required: true },
  audio: { type: String, required: true },
  currentTime: { type: Number, required: true },
  duration: { type: Number, default: 0 },
  title: { type: String, default: '' },
  poster: { type: String, default: '' },
  watchUrl: { type: String, default: '' },
  lastWatched: { type: Date, default: Date.now },
}, { timestamps: true });

// Unique per user + content (1 record per movie/episode, regardless of server/audio)
watchProgressSchema.index({ userId: 1, contentId: 1, isTVShow: 1, season: 1, episode: 1 }, { unique: true });
// Fast recent query
watchProgressSchema.index({ userId: 1, lastWatched: -1 });

const WatchProgress = mongoose.model('WatchProgress', watchProgressSchema);
module.exports = WatchProgress;
