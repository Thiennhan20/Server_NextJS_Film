/**
 * WebSocket Server — Watch Party + Global Chat
 * 
 * Namespace /watch-party  → Room-based, JWT authenticated
 * Default namespace /      → Global chat (legacy, giữ nguyên)
 */

const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const roomService = require('./services/roomService');

const GRACE_PERIOD_MS = 30000;   // 30 seconds
const HEARTBEAT_TIMEOUT_MS = 45000; // 45 seconds (3 missed heartbeats)

// ─── Tracking Maps ──────────────────────────────────────────

// Global chat
const onlineUsers = new Map(); // socketId → username

// Watch Party: track connections per room
// roomId → Map<userId, { socketId, username, heartbeatTimer, graceTimer }>
const roomConnections = new Map();

function initializeWebSocket(server) {
  const io = new Server(server, {
    cors: {
      origin: ["https://moviesaw.vercel.app", "http://localhost:3000"],
      methods: ["GET", "POST"],
      credentials: true
    }
  });

  // ════════════════════════════════════════════════════════════
  //  DEFAULT NAMESPACE — Global Chat (legacy, giữ nguyên)
  // ════════════════════════════════════════════════════════════

  io.on('connection', (socket) => {
    console.log('Chat user connected:', socket.id);

    socket.on('user_join', (username) => {
      onlineUsers.set(socket.id, username);
      io.emit('user_list', Array.from(onlineUsers.values()));
      io.emit('chat_message', {
        type: 'system',
        content: `${username} joined the chat room`,
        timestamp: new Date().toISOString()
      });
    });

    socket.on('chat_message', (message) => {
      const username = onlineUsers.get(socket.id);
      if (username) {
        io.emit('chat_message', {
          type: 'user',
          username: username,
          content: message,
          timestamp: new Date().toISOString()
        });
      }
    });

    socket.on('image_message', (imageData) => {
      const username = onlineUsers.get(socket.id);
      if (username) {
        io.emit('chat_message', {
          type: 'image',
          username: username,
          content: imageData,
          timestamp: new Date().toISOString()
        });
      }
    });

    socket.on('disconnect', () => {
      const username = onlineUsers.get(socket.id);
      if (username) {
        onlineUsers.delete(socket.id);
        io.emit('user_list', Array.from(onlineUsers.values()));
        io.emit('chat_message', {
          type: 'system',
          content: `${username} left the chat room`,
          timestamp: new Date().toISOString()
        });
      }
      console.log('Chat user disconnected:', socket.id);
    });
  });

  // ════════════════════════════════════════════════════════════
  //  WATCH PARTY NAMESPACE — /watch-party
  // ════════════════════════════════════════════════════════════

  const wpNamespace = io.of('/watch-party');

  // ─── JWT Authentication Middleware ────────────────────────

  wpNamespace.use(async (socket, next) => {
    const token = socket.handshake.auth?.token || socket.handshake.query?.token;

    if (!token) {
      return next(new Error('AUTH_ERROR: No token provided'));
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      socket.userId = decoded.userId;
      socket.username = decoded.name || decoded.username || 'User';
      socket.avatar = '';

      // Fetch name and avatar from database to ensure fresh and correct details
      try {
        const User = require('./models/User');
        const user = await User.findById(decoded.userId).select('name avatar');
        if (user) {
          if (user.name) socket.username = user.name;
          if (user.avatar) socket.avatar = user.avatar;
        }
      } catch (err) {
        console.error('Failed to fetch user details in WS auth middleware:', err);
      }

      next();
    } catch (err) {
      console.error('WS Auth error:', err.message);
      return next(new Error('AUTH_ERROR: Invalid or expired token'));
    }
  });

  // ─── Connection Handler ──────────────────────────────────

  wpNamespace.on('connection', (socket) => {
    console.log(`[WP] User connected: ${socket.username} (${socket.userId})`);

    let currentRoomId = null;

    // ─── JOIN_ROOM ──────────────────────────────────────────

    socket.on('JOIN_ROOM', async ({ room_id }) => {
      if (!room_id) {
        socket.emit('ERROR', { message: 'Room ID is required.' });
        return;
      }

      const roomId = room_id.toUpperCase();

      // Check room exists
      const room = await roomService.getRoom(roomId);
      if (!room) {
        socket.emit('ROOM_EXPIRED', {
          message: 'Room not found or has expired.'
        });
        return;
      }

      // Check if reconnecting from grace period
      const inGrace = await roomService.isInGracePeriod(roomId, socket.userId);
      if (inGrace) {
        // Cancel grace timer
        const roomConns = roomConnections.get(roomId);
        if (roomConns && roomConns.has(socket.userId)) {
          const connInfo = roomConns.get(socket.userId);
          if (connInfo.graceTimer) clearTimeout(connInfo.graceTimer);
        }
        await roomService.endGracePeriod(roomId, socket.userId);
        console.log(`[WP] User ${socket.username} reconnected to ${roomId} (grace period cancelled)`);
      }

      // Atomic join
      const joinResult = await roomService.joinRoom(roomId, socket.userId);
      if (!joinResult.success) {
        socket.emit('ERROR', {
          message: `This room is full (${room.max_users}/${room.max_users}). Please wait for someone to leave.`
        });
        return;
      }

      // Join Socket.IO room
      socket.join(`room:${roomId}`);
      currentRoomId = roomId;

      // Track connection
      if (!roomConnections.has(roomId)) {
        roomConnections.set(roomId, new Map());
      }
      const roomConns = roomConnections.get(roomId);
      
      // Clear old heartbeat timer if reconnecting
      if (roomConns.has(socket.userId)) {
        const old = roomConns.get(socket.userId);
        if (old.heartbeatTimer) clearTimeout(old.heartbeatTimer);
      }

      roomConns.set(socket.userId, {
        socketId: socket.id,
        username: socket.username,
        avatar: socket.avatar || '',
        heartbeatTimer: startHeartbeatTimer(socket, roomId),
        graceTimer: null,
      });

      // Get updated member count
      const memberCount = await roomService.getRoomMembers(roomId);
      const isUserHost = room.host_id === socket.userId;

      // Extract list of active room members from roomConnections Map
      const membersList = [];
      if (roomConns) {
        roomConns.forEach((conn, uid) => {
          membersList.push({
            user_id: uid,
            username: conn.username,
            avatar: conn.avatar || '',
            is_host: room.host_id === uid,
          });
        });
      }

      // Send room status to the joining user
      const roomStatus = {
        status: room.status,
        position_sec: room.current_pos,
        force_sync: room.force_sync,
        member_count: memberCount.length,
        max_users: room.max_users,
        title: room.title,
        host_name: room.host_name,
        is_host: isUserHost,
        members: membersList,
        audio: room.audio || '',
        content_type: room.content_type || '',
        season: room.season || null,
        current_episode: room.current_episode || null,
        episode_playlist: room.episode_playlist || [],
      };

      // Host gets stream_url, viewer gets it via WebSocket (needed for HLS.js)
      roomStatus.stream_url = room.stream_url;

      socket.emit('ROOM_STATUS', roomStatus);

      // Notify others in room (always notify, including reconnects from grace period)
      socket.to(`room:${roomId}`).emit('USER_JOINED', {
        user_id: socket.userId,
        username: socket.username,
        avatar: socket.avatar || '',
        member_count: memberCount.length,
        is_host: isUserHost,
      });

      console.log(`[WP] ${socket.username} joined ${roomId} (${joinResult.reason})`);
    });

    // ─── HOST-ONLY: PLAY / PAUSE / SEEK ─────────────────────

    socket.on('PLAY', async ({ position_sec }) => {
      if (!currentRoomId) return;
      if (!await roomService.isHost(currentRoomId, socket.userId)) return;

      await roomService.updateStatus(currentRoomId, 'PLAYING');
      await roomService.updatePosition(currentRoomId, position_sec || 0);

      wpNamespace.to(`room:${currentRoomId}`).emit('PLAY', {
        position_sec: position_sec || 0,
      });
    });

    socket.on('PAUSE', async ({ position_sec }) => {
      if (!currentRoomId) return;
      if (!await roomService.isHost(currentRoomId, socket.userId)) return;

      await roomService.updateStatus(currentRoomId, 'PAUSED');
      await roomService.updatePosition(currentRoomId, position_sec || 0);

      wpNamespace.to(`room:${currentRoomId}`).emit('PAUSE', {
        position_sec: position_sec || 0,
      });
    });

    socket.on('SEEK', async ({ position_sec }) => {
      if (!currentRoomId) return;

      const room = await roomService.getRoom(currentRoomId);
      if (!room) return;

      const isUserHost = room.host_id === socket.userId;

      if (isUserHost) {
        // Host seek → broadcast to all
        await roomService.updatePosition(currentRoomId, position_sec);
        wpNamespace.to(`room:${currentRoomId}`).emit('SEEK', { position_sec });
      } else if (!room.force_sync) {
        // Viewer seek (only when force_sync is off) → only applies to themselves
        socket.emit('SEEK', { position_sec });
      }
      // If force_sync is true and viewer tries to seek → ignore
    });

    // ─── HOST-ONLY: SYNC_TOGGLE ─────────────────────────────

    socket.on('SYNC_TOGGLE', async ({ force_sync }) => {
      if (!currentRoomId) return;
      if (!await roomService.isHost(currentRoomId, socket.userId)) return;

      await roomService.updateRoom(currentRoomId, { force_sync: force_sync ? 'true' : 'false' });

      wpNamespace.to(`room:${currentRoomId}`).emit('SYNC_TOGGLE', {
        force_sync: !!force_sync,
      });
    });

    // ─── HOST-ONLY: CHANGE (stream URL) ─────────────────────

    socket.on('CHANGE', async ({ stream_url, title, current_episode }) => {
      if (!currentRoomId) return;
      if (!await roomService.isHost(currentRoomId, socket.userId)) return;

      if (stream_url && !roomService.isValidStreamUrl(stream_url)) {
        socket.emit('ERROR', {
          message: 'Invalid stream URL. Please provide a valid .m3u8 link.'
        });
        return;
      }

      await roomService.updateStream(currentRoomId, stream_url, title, { currentEpisode: current_episode });

      wpNamespace.to(`room:${currentRoomId}`).emit('CHANGE', {
        stream_url,
        title: title || '',
        current_episode: current_episode || null,
      });
    });

    // ─── HOST-ONLY: KICK ────────────────────────────────────

    socket.on('KICK', async ({ target_user_id }) => {
      if (!currentRoomId) return;
      if (!await roomService.isHost(currentRoomId, socket.userId)) return;
      if (target_user_id === socket.userId) return; // Can't kick yourself

      // Remove from Redis
      await roomService.leaveRoom(currentRoomId, target_user_id);

      // Find target socket and kick
      const roomConns = roomConnections.get(currentRoomId);
      if (roomConns && roomConns.has(target_user_id)) {
        const targetConn = roomConns.get(target_user_id);
        const targetSocket = wpNamespace.sockets.get(targetConn.socketId);
        if (targetSocket) {
          targetSocket.emit('KICK', {
            user_id: target_user_id,
            message: 'You have been removed from the room.'
          });
          targetSocket.leave(`room:${currentRoomId}`);
        }
        if (targetConn.heartbeatTimer) clearTimeout(targetConn.heartbeatTimer);
        roomConns.delete(target_user_id);
      }

      // Notify remaining members
      const members = await roomService.getRoomMembers(currentRoomId);
      wpNamespace.to(`room:${currentRoomId}`).emit('USER_LEFT', {
        user_id: target_user_id,
        username: 'User',
        member_count: members.length,
      });
    });

    // ─── ALL: SYNC_POSITION (host sends every 10s) ──────────

    socket.on('SYNC_POSITION', async ({ position_sec }) => {
      if (!currentRoomId) return;
      if (!await roomService.isHost(currentRoomId, socket.userId)) return;

      await roomService.updatePosition(currentRoomId, position_sec);

      // Broadcast to viewers for drift correction
      socket.to(`room:${currentRoomId}`).emit('SYNC_POSITION', {
        position_sec,
      });
    });

    // ─── HOST-ONLY: BUFFERING / BUFFER_END ──────────────────

    socket.on('HOST_BUFFERING', async () => {
      if (!currentRoomId) return;
      if (!await roomService.isHost(currentRoomId, socket.userId)) return;

      socket.to(`room:${currentRoomId}`).emit('HOST_BUFFERING');
    });

    socket.on('HOST_BUFFER_END', async ({ position_sec }) => {
      if (!currentRoomId) return;
      if (!await roomService.isHost(currentRoomId, socket.userId)) return;

      if (position_sec !== undefined) {
        await roomService.updatePosition(currentRoomId, position_sec);
      }

      socket.to(`room:${currentRoomId}`).emit('HOST_BUFFER_END', {
        position_sec: position_sec || 0,
      });
    });

    // ─── ALL: HEARTBEAT ─────────────────────────────────────

    socket.on('HEARTBEAT', () => {
      if (!currentRoomId) return;

      const roomConns = roomConnections.get(currentRoomId);
      if (roomConns && roomConns.has(socket.userId)) {
        const connInfo = roomConns.get(socket.userId);
        // Reset heartbeat timer
        if (connInfo.heartbeatTimer) clearTimeout(connInfo.heartbeatTimer);
        connInfo.heartbeatTimer = startHeartbeatTimer(socket, currentRoomId);
      }
    });

    // ─── ALL: CHAT ──────────────────────────────────────────

    socket.on('CHAT', ({ message }) => {
      if (!currentRoomId) return;
      if (!message || typeof message !== 'string' || message.trim().length === 0) return;

      wpNamespace.to(`room:${currentRoomId}`).emit('CHAT', {
        user_id: socket.userId,
        username: socket.username,
        message: message.trim().substring(0, 500), // Max 500 chars
        sent_at: new Date().toISOString(),
      });
    });

    // ─── ALL: EMOJI_REACTION ────────────────────────────────

    socket.on('EMOJI_REACTION', ({ emoji }) => {
      if (!currentRoomId) return;
      if (!emoji) return;

      wpNamespace.to(`room:${currentRoomId}`).emit('EMOJI_REACTION', {
        user_id: socket.userId,
        username: socket.username,
        emoji,
        sent_at: new Date().toISOString(),
      });
    });

    // ─── LEAVE_ROOM (intentional exit — skip grace period) ────

    let leftIntentionally = false;

    socket.on('LEAVE_ROOM', async () => {
      if (!currentRoomId) return;

      leftIntentionally = true;
      console.log(`[WP] ${socket.username} intentionally left ${currentRoomId}`);

      // Immediately remove from room (no grace period)
      await roomService.leaveRoom(currentRoomId, socket.userId);

      // Notify others
      const members = await roomService.getRoomMembers(currentRoomId);
      socket.to(`room:${currentRoomId}`).emit('USER_LEFT', {
        user_id: socket.userId,
        username: socket.username,
        member_count: members.length,
      });

      // Clean up connection tracking
      const roomConns = roomConnections.get(currentRoomId);
      if (roomConns) {
        const connInfo = roomConns.get(socket.userId);
        if (connInfo) {
          if (connInfo.heartbeatTimer) clearTimeout(connInfo.heartbeatTimer);
          if (connInfo.graceTimer) clearTimeout(connInfo.graceTimer);
        }
        roomConns.delete(socket.userId);
        if (roomConns.size === 0) {
          roomConnections.delete(currentRoomId);
        }
      }

      socket.leave(`room:${currentRoomId}`);
      currentRoomId = null;
    });

    // ─── DISCONNECT ─────────────────────────────────────────

    socket.on('disconnect', async () => {
      console.log(`[WP] User disconnected: ${socket.username} (${socket.userId})`);

      if (!currentRoomId) return;

      // If user already left intentionally, skip grace period
      if (leftIntentionally) {
        console.log(`[WP] ${socket.username} disconnected after intentional leave — no grace period`);
        return;
      }

      const roomConns = roomConnections.get(currentRoomId);
      if (!roomConns || !roomConns.has(socket.userId)) return;

      const connInfo = roomConns.get(socket.userId);
      if (connInfo.heartbeatTimer) clearTimeout(connInfo.heartbeatTimer);

      // Start grace period (keep slot reserved for reconnection)
      await roomService.startGracePeriod(currentRoomId, socket.userId);

      // ★ Immediately notify others that user left (no delay!)
      const members = await roomService.getRoomMembers(currentRoomId);
      socket.to(`room:${currentRoomId}`).emit('USER_LEFT', {
        user_id: socket.userId,
        username: socket.username,
        member_count: Math.max(0, members.length - 1), // -1 because user is still in Redis during grace
      });

      const graceTimer = setTimeout(async () => {
        await handleGraceExpired(currentRoomId, socket.userId, socket.username);
      }, GRACE_PERIOD_MS);

      connInfo.graceTimer = graceTimer;
      connInfo.socketId = null; // Socket is gone

      console.log(`[WP] Grace period started for ${socket.username} in ${currentRoomId} (30s)`);
    });
  });

  // ─── Grace Period Expiry Handler ──────────────────────────

  async function handleGraceExpired(roomId, userId, username) {
    console.log(`[WP] Grace period expired for ${username} in ${roomId}`);

    await roomService.endGracePeriod(roomId, userId);

    // Remove user from room (both host and viewer)
    await roomService.leaveRoom(roomId, userId);

    // Clean up connection tracking
    const roomConns = roomConnections.get(roomId);
    if (roomConns) {
      roomConns.delete(userId);
      if (roomConns.size === 0) {
        roomConnections.delete(roomId);
      }
    }

    console.log(`[WP] ${username} permanently left ${roomId}`);
  }

  // ─── Heartbeat Timer ──────────────────────────────────────

  function startHeartbeatTimer(socket, roomId) {
    return setTimeout(async () => {
      console.log(`[WP] Heartbeat timeout for ${socket.username} in ${roomId}`);
      // Treat as disconnect → trigger grace period
      socket.disconnect(true);
    }, HEARTBEAT_TIMEOUT_MS);
  }

  return io;
}

module.exports = initializeWebSocket;
