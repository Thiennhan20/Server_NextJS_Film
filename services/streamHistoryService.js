const crypto = require('crypto');
const mongoose = require('mongoose');
const StreamHistory = require('../models/StreamHistory');

const MAX_HISTORY_ITEMS = 100;

function sanitizeText(value, maxLength = 300) {
  if (value === undefined || value === null) return '';
  return String(value).trim().slice(0, maxLength);
}

function normalizeNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function getStreamKey(streamUrl) {
  return crypto
    .createHash('sha256')
    .update(String(streamUrl).trim())
    .digest('hex');
}

function toClientItem(doc) {
  return {
    id: String(doc._id),
    room_id: doc.roomId || '',
    title: doc.title || '',
    stream_url: doc.streamUrl || '',
    movie_id: doc.movieId || '',
    audio: doc.audio || '',
    content_type: doc.contentType || '',
    season: doc.season ?? null,
    episode: doc.episode ?? null,
    created_count: doc.createdCount || 0,
    created_at: doc.createdAt,
    last_created_at: doc.lastCreatedAt,
    episode_playlist: doc.episodePlaylist || [],
    poster: doc.poster || '',
  };
}

async function trimHistory(userId) {
  const overflow = await StreamHistory.find({ userId })
    .sort({ lastCreatedAt: -1 })
    .skip(MAX_HISTORY_ITEMS)
    .select('_id')
    .lean();

  if (overflow.length === 0) return;

  await StreamHistory.deleteMany({
    userId,
    _id: { $in: overflow.map((item) => item._id) },
  });
}

async function recordCreatedStream({
  hostId,
  roomId,
  title,
  streamUrl,
  movieId,
  audio,
  contentType,
  season,
  episode,
  episodePlaylist,
  poster,
}) {
  const cleanedStreamUrl = sanitizeText(streamUrl, 3000);
  if (!hostId || !cleanedStreamUrl) return null;

  const now = new Date();
  const streamKey = getStreamKey(cleanedStreamUrl);
  const sanitizedContentType = contentType === 'tvshow' ? 'tvshow' : contentType === 'movie' ? 'movie' : '';

  const updates = {
    roomId: sanitizeText(roomId, 80),
    title: sanitizeText(title, 300),
    streamUrl: cleanedStreamUrl,
    movieId: sanitizeText(movieId, 80),
    audio: sanitizeText(audio, 40),
    contentType: sanitizedContentType,
    season: normalizeNumber(season),
    episode: normalizeNumber(episode),
    lastCreatedAt: now,
    poster: sanitizeText(poster, 600),
  };

  if (Array.isArray(episodePlaylist) && episodePlaylist.length > 0) {
    updates.episodePlaylist = episodePlaylist;
  }

  const doc = await StreamHistory.findOneAndUpdate(
    { userId: hostId, streamKey },
    {
      $set: updates,
      $setOnInsert: {
        userId: hostId,
        streamKey,
      },
      $inc: {
        createdCount: 1,
      },
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  ).lean();

  await trimHistory(hostId);
  return doc ? toClientItem(doc) : null;
}

async function listUserStreams(userId, limit = 20) {
  const safeLimit = Math.min(Math.max(Number(limit) || 20, 1), MAX_HISTORY_ITEMS);
  const items = await StreamHistory.find({ userId })
    .sort({ lastCreatedAt: -1 })
    .limit(safeLimit)
    .lean();

  return items.map(toClientItem);
}

async function updateStreamHistoryMetadata({
  userId,
  streamUrl,
  season,
  episode,
  episodePlaylist,
  poster,
}) {
  const cleanedStreamUrl = sanitizeText(streamUrl, 3000);
  if (!userId || !cleanedStreamUrl) return null;

  const streamKey = getStreamKey(cleanedStreamUrl);
  const updates = {};

  if (season !== undefined && season !== null) {
    updates.season = normalizeNumber(season);
  }
  if (episode !== undefined && episode !== null) {
    updates.episode = normalizeNumber(episode);
  }
  if (Array.isArray(episodePlaylist) && episodePlaylist.length > 0) {
    updates.episodePlaylist = episodePlaylist;
  }
  if (poster !== undefined && poster !== null) {
    updates.poster = sanitizeText(poster, 600);
  }

  if (Object.keys(updates).length === 0) return null;

  const doc = await StreamHistory.findOneAndUpdate(
    { userId, streamKey },
    { $set: updates },
    { new: true }
  ).lean();

  return doc ? toClientItem(doc) : null;
}

async function deleteUserStream(userId, historyId) {
  if (!mongoose.Types.ObjectId.isValid(historyId)) return false;
  const result = await StreamHistory.deleteOne({ _id: historyId, userId });
  return result.deletedCount > 0;
}

module.exports = {
  recordCreatedStream,
  updateStreamHistoryMetadata,
  listUserStreams,
  deleteUserStream,
  MAX_HISTORY_ITEMS,
};

