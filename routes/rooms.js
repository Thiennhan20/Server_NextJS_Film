/**
 * REST API Routes — Watch Party Rooms
 * 
 * POST   /api/rooms            → Tạo phòng mới
 * GET    /api/rooms/:id        → Lấy thông tin phòng
 * DELETE /api/rooms/:id        → Host kết thúc phòng
 * PATCH  /api/rooms/:id/stream → Host đổi link phim
 */

const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const roomService = require('../services/roomService');
const streamHistoryService = require('../services/streamHistoryService');
const redisClient = require('../config/redis');

const COMMUNITY_PICKS_CACHE_KEY = 'cache:community_picks';
const COMMUNITY_PICKS_TTL = 8 * 3600; // 8 hours (28,800 seconds)

// ─── GET /api/rooms/public — Public listing (no auth required) ──
router.get('/public', async (req, res) => {
  try {
    const rooms = await roomService.listActiveRooms();
    // Return limited info for public view (no stream_url)
    const publicRooms = rooms.map(r => ({
      room_id: r.room_id,
      title: r.title,
      poster: r.poster || '',
      host_name: r.host_name,
      host_avatar: r.host_avatar,
      host_id: r.host_id,
      status: r.status,
      member_count: r.member_count,
      max_users: r.max_users,
      created_at: r.created_at,
      ttl_seconds: r.ttl_seconds,
      content_type: r.content_type || '',
      season: r.season || null,
      current_episode: r.current_episode || null,
      movie_id: r.movie_id || '',
    }));
    res.json({
      rooms: publicRooms,
      total_rooms: publicRooms.length,
    });
  } catch (error) {
    console.error('Public list rooms error:', error);
    res.status(500).json({ error: 'Failed to list rooms.' });
  }
});

// ─── GET /api/rooms/community-picks — 10 random community movies for Quick Pick & Create (Public & Secure) ──
router.get('/community-picks', async (req, res) => {
  try {
    const isRefresh = req.query.refresh === 'true';

    // 1. Check Redis cache first (if not force-refreshing)
    if (!isRefresh) {
      try {
        const cached = await redisClient.get(COMMUNITY_PICKS_CACHE_KEY);
        if (cached) {
          const items = typeof cached === 'string' ? JSON.parse(cached) : cached;
          if (Array.isArray(items) && items.length > 0) {
            return res.json({
              success: true,
              items,
              cached: true,
            });
          }
        }
      } catch (redisErr) {
        console.warn('Redis GET community-picks cache error:', redisErr.message);
      }
    }

    const WatchProgress = require('../models/WatchProgress');
    const StreamHistory = require('../models/StreamHistory');

    // 1. Sample from WatchProgress grouped by title to ensure distinct movies from different users
    const wpPicks = await WatchProgress.aggregate([
      { 
        $match: { 
          watchUrl: { $regex: '^https?://' },
          title: { $exists: true, $ne: '' }
        } 
      },
      { $sample: { size: 35 } },
      {
        $group: {
          _id: { $toLower: '$title' },
          contentId: { $first: '$contentId' },
          title: { $first: '$title' },
          poster: { $first: '$poster' },
          streamUrl: { $first: '$watchUrl' },
          type: { $first: { $cond: [{ $eq: ['$isTVShow', true] }, 'tvshow', 'movie'] } },
          season: { $first: '$season' },
          episode: { $first: '$episode' },
          audio: { $first: '$audio' }
        }
      },
      { $sample: { size: 10 } }
    ]);

    const cleanPoster = (url) => {
      if (!url) return '';
      if (url.lastIndexOf('http') > 0) {
        return url.substring(url.lastIndexOf('http'));
      }
      return url;
    };

    let combined = wpPicks.map(p => ({
      id: `pick-${p.contentId || p.title}`,
      movieId: String(p.contentId || ''),
      title: p.title,
      poster: cleanPoster(p.poster),
      streamUrl: p.streamUrl,
      type: p.type || 'movie',
      season: p.season ?? null,
      episode: p.episode ?? null,
      audio: p.audio || ''
    }));

    // 2. If fewer than 10, fill in from StreamHistory
    if (combined.length < 10) {
      const seenTitles = new Set(combined.map(c => c.title.toLowerCase()));
      const shPicks = await StreamHistory.aggregate([
        {
          $match: {
            streamUrl: { $regex: '^https?://' },
            title: { $exists: true, $ne: '' }
          }
        },
        { $sample: { size: 25 } },
        {
          $group: {
            _id: { $toLower: '$title' },
            movieId: { $first: '$movieId' },
            title: { $first: '$title' },
            poster: { $first: '$poster' },
            streamUrl: { $first: '$streamUrl' },
            type: { $first: { $cond: [{ $eq: ['$contentType', 'tvshow'] }, 'tvshow', 'movie'] } },
            season: { $first: '$season' },
            episode: { $first: '$episode' },
            audio: { $first: '$audio' }
          }
        }
      ]);

      for (const sh of shPicks) {
        if (!seenTitles.has(sh.title.toLowerCase()) && combined.length < 10) {
          seenTitles.add(sh.title.toLowerCase());
          combined.push({
            id: `pick-${sh.movieId || sh.title}`,
            movieId: String(sh.movieId || ''),
            title: sh.title,
            poster: cleanPoster(sh.poster),
            streamUrl: sh.streamUrl,
            type: sh.type || 'movie',
            season: sh.season ?? null,
            episode: sh.episode ?? null,
            audio: sh.audio || ''
          });
        }
      }
    }

    // 3. Save to Redis cache for 8 hours
    if (Array.isArray(combined) && combined.length > 0) {
      try {
        await redisClient.set(COMMUNITY_PICKS_CACHE_KEY, combined, COMMUNITY_PICKS_TTL);
      } catch (redisErr) {
        console.warn('Redis SET community-picks cache error:', redisErr.message);
      }
    }

    res.json({
      success: true,
      items: combined,
      cached: false,
    });
  } catch (error) {
    console.error('Community picks error:', error);
    res.status(500).json({ error: 'Failed to get community picks.' });
  }
});

// ─── GET /api/rooms — Danh sách phòng đang hoạt động ────────

router.get('/', auth, async (req, res) => {
  try {
    const rooms = await roomService.listActiveRooms();
    res.json({
      rooms,
      total_rooms: rooms.length,
      max_rooms: roomService.MAX_CONCURRENT_ROOMS,
    });
  } catch (error) {
    console.error('List rooms error:', error);
    res.status(500).json({ error: 'Failed to list rooms.' });
  }
});

// ─── GET /api/rooms/check-duplicate — Check if user already has room for same movie+audio ──
router.get('/check-duplicate', auth, async (req, res) => {
  try {
    const userId = req.user;
    const { movieId, audio, season } = req.query;

    if (!movieId) {
      return res.status(400).json({ error: 'movieId is required.' });
    }

    const duplicate = await roomService.checkDuplicateRoom(
      userId,
      String(movieId),
      audio ? String(audio) : '',
      season ? String(season) : ''
    );
    if (duplicate) {
      return res.json({
        duplicate: true,
        existing_room_id: duplicate.room_id,
        title: duplicate.title,
        audio: duplicate.audio,
        season: duplicate.season,
      });
    }

    res.json({ duplicate: false });
  } catch (error) {
    console.error('Check duplicate error:', error);
    res.status(500).json({ error: 'Failed to check for duplicates.' });
  }
});

router.get('/history', auth, async (req, res) => {
  try {
    const limit = req.query.limit ? Number(req.query.limit) : 20;
    const items = await streamHistoryService.listUserStreams(req.user, limit);
    res.json({ items });
  } catch (error) {
    console.error('List stream history error:', error);
    res.status(500).json({ error: 'Failed to list stream history.' });
  }
});

router.delete('/history/:historyId', auth, async (req, res) => {
  try {
    const deleted = await streamHistoryService.deleteUserStream(req.user, req.params.historyId);
    if (!deleted) {
      return res.status(404).json({ error: 'Saved stream not found.' });
    }
    res.json({ ok: true });
  } catch (error) {
    console.error('Delete stream history error:', error);
    res.status(500).json({ error: 'Failed to delete saved stream.' });
  }
});

// ─── POST /api/rooms — Tạo phòng mới ───────────────────────

router.post('/', auth, async (req, res) => {
  try {
    const { title, stream_url, movie_id, audio, content_type, season, episode, episode_playlist, poster } = req.body;
    const userId = req.user; // From auth middleware

    // Validate stream URL if provided
    if (stream_url && !roomService.isValidStreamUrl(stream_url)) {
      return res.status(400).json({
        error: 'Invalid stream URL. Please provide a valid .m3u8 link.'
      });
    }

    // Get user info for host_name and avatar
    const User = require('../models/User');
    const user = await User.findById(userId).select('name avatar');
    const hostName = user?.name || 'Host';
    const hostAvatar = user?.avatar || '';

    const result = await roomService.createRoom({
      hostId: userId,
      hostName,
      hostAvatar,
      streamUrl: stream_url || '',
      title: title || '',
      movieId: movie_id || '',
      audio: audio || '',
      contentType: content_type || '',
      season: season || '',
      episode: episode || '',
      episodePlaylist: episode_playlist || [],
      poster: poster || '',
    });

    if (!result.success) {
      const status = result.code === 'CAPACITY_FULL' ? 503
        : result.code === 'DUPLICATE_ROOM' ? 409
        : 500;
      return res.status(status).json({
        error: result.error,
        code: result.code,
        active_count: result.activeCount,
        max_rooms: result.maxRooms,
        existing_room_id: result.existingRoomId,
      });
    }

    try {
      await streamHistoryService.recordCreatedStream({
        hostId: userId,
        roomId: result.roomId,
        title: title || '',
        streamUrl: stream_url || '',
        movieId: movie_id || '',
        audio: audio || '',
        contentType: content_type || '',
        season,
        episode,
        episodePlaylist: episode_playlist || [],
        poster: poster || '',
      });
    } catch (historyError) {
      console.error('Record stream history error:', historyError);
    }

    res.status(201).json({
      room_id: result.roomId,
      room_link: `/streaming-room?room=${result.roomId}`,
      expires_at: result.expiresAt,
    });
  } catch (error) {
    console.error('Create room error:', error);
    res.status(500).json({ error: 'Unable to create room. Please try again.' });
  }
});

// ─── GET /api/rooms/:id — Lấy thông tin phòng ──────────────

router.get('/:id', auth, async (req, res) => {
  try {
    const roomId = req.params.id.toUpperCase();
    const userId = req.user;

    const room = await roomService.getRoom(roomId);
    if (!room) {
      return res.status(404).json({
        error: 'Room not found or has expired.'
      });
    }

    // Build response — viewer doesn't get stream_url
    const response = {
      room_id: room.room_id,
      title: room.title,
      status: room.status,
      member_count: room.member_count,
      max_users: room.max_users,
      force_sync: room.force_sync,
      created_at: room.created_at,
      expires_at: room.expires_at,
      current_pos: room.current_pos,
      host_name: room.host_name,
      audio: room.audio,
      content_type: room.content_type,
      season: room.season,
      current_episode: room.current_episode,
      episode_playlist: room.episode_playlist || [],
      movie_id: room.movie_id || '',
    };

    // Only host can see stream_url via REST
    if (room.host_id === userId) {
      response.stream_url = room.stream_url;
      response.is_host = true;
    } else {
      response.is_host = false;
    }

    res.json(response);
  } catch (error) {
    console.error('Get room error:', error);
    res.status(500).json({ error: 'Failed to get room info.' });
  }
});

// ─── DELETE /api/rooms/:id — Host kết thúc phòng ────────────

router.delete('/:id', auth, async (req, res) => {
  try {
    const roomId = req.params.id.toUpperCase();
    const userId = req.user;

    // Check room exists
    const room = await roomService.getRoom(roomId);
    if (!room) {
      return res.status(404).json({
        error: 'Room not found or has expired.'
      });
    }

    // Only host can delete
    if (room.host_id !== userId) {
      return res.status(403).json({
        error: 'Only the host can close this room.'
      });
    }

    // Delete room from Redis
    await roomService.deleteRoom(roomId);

    // Notify WebSocket clients (if io instance is available)
    const io = req.app.get('io');
    if (io) {
      io.to(`room:${roomId}`).emit('ROOM_CLOSED', {
        message: 'Host ended the session. Redirecting in 5 seconds...'
      });
    }

    res.json({ message: 'Room closed successfully.' });
  } catch (error) {
    console.error('Delete room error:', error);
    res.status(500).json({ error: 'Failed to close room.' });
  }
});

// ─── PATCH /api/rooms/:id/stream — Host đổi link phim ──────

router.patch('/:id/stream', auth, async (req, res) => {
  try {
    const roomId = req.params.id.toUpperCase();
    const userId = req.user;
    const { stream_url, title, current_episode } = req.body;

    // Validate stream URL
    if (!stream_url || !roomService.isValidStreamUrl(stream_url)) {
      return res.status(400).json({
        error: 'Invalid stream URL. Please provide a valid .m3u8 link.'
      });
    }

    // Check room exists
    const room = await roomService.getRoom(roomId);
    if (!room) {
      return res.status(404).json({
        error: 'Room not found or has expired.'
      });
    }

    // Only host can change stream
    if (room.host_id !== userId) {
      return res.status(403).json({
        error: 'Only the host can change the stream.'
      });
    }

    // Update stream in Redis
    await roomService.updateStream(roomId, stream_url, title, { currentEpisode: current_episode });

    try {
      await streamHistoryService.recordCreatedStream({
        hostId: userId,
        roomId,
        title: title || room.title,
        streamUrl: stream_url,
        movieId: room.movie_id || '',
        audio: room.audio || '',
        contentType: room.content_type || '',
        season: room.season,
        episode: current_episode || room.current_episode,
        episodePlaylist: room.episode_playlist || [],
      });
    } catch (historyError) {
      console.error('Record stream history error:', historyError);
    }

    // Notify WebSocket clients
    const io = req.app.get('io');
    if (io) {
      const watchPartyNamespace = io.of ? io.of('/watch-party') : io;
      watchPartyNamespace.to(`room:${roomId}`).emit('CHANGE', {
        stream_url,
        title: title || room.title,
        current_episode: current_episode || room.current_episode,
      });
    }

    res.json({ message: 'Stream updated successfully.' });
  } catch (error) {
    console.error('Update stream error:', error);
    res.status(500).json({ error: 'Failed to update stream.' });
  }
});

// ─── PATCH /api/rooms/:id/episode-playlist — Host lưu danh sách tập TV ──

router.patch('/:id/episode-playlist', auth, async (req, res) => {
  try {
    const roomId = req.params.id.toUpperCase();
    const userId = req.user;
    const { content_type, season, current_episode, episode_playlist } = req.body;

    const room = await roomService.getRoom(roomId);
    if (!room) {
      return res.status(404).json({
        error: 'Room not found or has expired.'
      });
    }

    if (room.host_id !== userId) {
      return res.status(403).json({
        error: 'Only the host can update the episode playlist.'
      });
    }

    const sanitizedPlaylist = await roomService.updateEpisodePlaylist(roomId, {
      contentType: content_type,
      season,
      currentEpisode: current_episode,
      episodePlaylist: episode_playlist || [],
    });

    try {
      await streamHistoryService.updateStreamHistoryMetadata({
        userId,
        streamUrl: room.stream_url,
        season: season || room.season,
        episode: current_episode || room.current_episode,
        episodePlaylist: sanitizedPlaylist,
      });
    } catch (historyError) {
      // Silent check
    }
    const io = req.app.get('io');
    if (io && sanitizedPlaylist.length > 0) {
      const watchPartyNamespace = io.of ? io.of('/watch-party') : io;
      watchPartyNamespace.to(`room:${roomId}`).emit('EPISODE_PLAYLIST', {
        content_type: content_type === 'tvshow' ? 'tvshow' : room.content_type,
        season: season || room.season,
        current_episode: current_episode || room.current_episode,
        episode_playlist: sanitizedPlaylist,
      });
    }

    res.json({
      message: 'Episode playlist updated successfully.',
      episode_count: sanitizedPlaylist.length,
    });
  } catch (error) {
    console.error('Update episode playlist error:', error);
    res.status(500).json({ error: 'Failed to update episode playlist.' });
  }
});

module.exports = router;
