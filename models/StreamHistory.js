const mongoose = require('mongoose');

const streamHistorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  streamKey: { type: String, required: true },
  roomId: { type: String, default: '' },
  title: { type: String, default: '', maxlength: 300 },
  streamUrl: { type: String, required: true, maxlength: 3000 },
  movieId: { type: String, default: '' },
  audio: { type: String, default: '' },
  contentType: { type: String, enum: ['movie', 'tvshow', ''], default: '' },
  season: { type: Number, default: null },
  episode: { type: Number, default: null },
  createdCount: { type: Number, default: 0 },
  lastCreatedAt: { type: Date, default: Date.now },
  episodePlaylist: { type: Array, default: [] },
  poster: { type: String, default: '' },
}, { timestamps: true });

streamHistorySchema.index({ userId: 1, streamKey: 1 }, { unique: true });
streamHistorySchema.index({ userId: 1, lastCreatedAt: -1 });

const StreamHistory = mongoose.model('StreamHistory', streamHistorySchema);
module.exports = StreamHistory;
