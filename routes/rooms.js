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

// ─── GET /api/rooms/public — Public listing (no auth required) ──
router.get('/public', async (req, res) => {
  try {
    const rooms = await roomService.listActiveRooms();
    // Return limited info for public view (no stream_url)
    const publicRooms = rooms.map(r => ({
      room_id: r.room_id,
      title: r.title,
      host_name: r.host_name,
      host_avatar: r.host_avatar,
      host_id: r.host_id,
      status: r.status,
      member_count: r.member_count,
      max_users: r.max_users,
      created_at: r.created_at,
      ttl_seconds: r.ttl_seconds,
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

// ─── POST /api/rooms — Tạo phòng mới ───────────────────────

router.post('/', auth, async (req, res) => {
  try {
    const { title, stream_url } = req.body;
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
    });

    if (!result.success) {
      const status = result.code === 'CAPACITY_FULL' ? 503 : 500;
      return res.status(status).json({
        error: result.error,
        code: result.code,
        active_count: result.activeCount,
        max_rooms: result.maxRooms,
      });
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
    const { stream_url, title } = req.body;

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
    await roomService.updateStream(roomId, stream_url, title);

    // Notify WebSocket clients
    const io = req.app.get('io');
    if (io) {
      io.to(`room:${roomId}`).emit('CHANGE', {
        stream_url,
        title: title || room.title,
      });
    }

    res.json({ message: 'Stream updated successfully.' });
  } catch (error) {
    console.error('Update stream error:', error);
    res.status(500).json({ error: 'Failed to update stream.' });
  }
});

module.exports = router;
