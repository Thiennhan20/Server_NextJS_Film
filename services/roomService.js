/**
 * Room Service — Quản lý phòng Watch Party trên Redis
 * 
 * Cấu trúc key:
 *   room:{room_id}         → Hash: thông tin phòng
 *   room:{room_id}:users   → Set: danh sách user_id trong phòng
 *   room:{room_id}:grace   → Hash: user_id đang trong grace period
 * 
 * TTL: 21600 giây (6 tiếng)
 */

const redis = require('../config/redis');

const ROOM_TTL = 21600; // 6 hours in seconds
const MAX_USERS = 2;
const ROOM_ID_LENGTH = 6;
const MAX_ROOM_ID_RETRIES = 5;
const MAX_CONCURRENT_ROOMS = 30; // Render Free tier capacity limit

// ─── Helpers ────────────────────────────────────────────────

/**
 * Generate random ROOM-XXXXXX ID
 */
function generateRoomId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = 'ROOM-';
  for (let i = 0; i < ROOM_ID_LENGTH; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

/**
 * Validate .m3u8 URL
 */
function isValidStreamUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

function hasRoomPlayed(data) {
  const status = data?.status || 'WAITING';
  return data?.has_played === 'true' ||
    status === 'PLAYING' ||
    status === 'PAUSED' ||
    status === 'ENDED' ||
    (parseFloat(data?.current_pos) || 0) > 0;
}

async function normalizeEmptyRoomStatus(roomId, roomData = null, memberCount = null) {
  const roomKey = `room:${roomId}`;
  const data = roomData || await redis.hgetall(roomKey);
  if (!data || Object.keys(data).length === 0) return null;

  const count = memberCount !== null
    ? memberCount
    : await redis.scard(`room:${roomId}:users`);

  if (count > 0) {
    return {
      status: data.status || 'WAITING',
      hasPlayed: hasRoomPlayed(data),
      memberCount: count,
      changed: false,
    };
  }

  const hasPlayed = hasRoomPlayed(data);
  const nextStatus = hasPlayed ? 'PAUSED' : 'WAITING';
  const updates = {};

  if ((data.status || 'WAITING') !== nextStatus) {
    updates.status = nextStatus;
  }
  if (hasPlayed && data.has_played !== 'true') {
    updates.has_played = 'true';
  }

  if (Object.keys(updates).length > 0) {
    await redis.hmset(roomKey, updates);
  }

  return {
    status: nextStatus,
    hasPlayed,
    memberCount: 0,
    changed: Object.keys(updates).length > 0,
  };
}

// ─── Room CRUD ──────────────────────────────────────────────

/**
 * Create a new room
 * @param {Object} params
 * @param {string} params.hostId - User ID of the host
 * @param {string} params.hostName - Display name of the host
 * @param {string} params.hostAvatar - Avatar URL of the host
 * @param {string} params.streamUrl - HLS stream URL
 * @param {string} params.title - Movie/show title
 * @returns {{ success: boolean, roomId?: string, error?: string }}
 */
async function createRoom({ hostId, hostName, hostAvatar, streamUrl, title, movieId, audio }) {
  // Check capacity limit
  const activeCount = await countActiveRooms();
  if (activeCount >= MAX_CONCURRENT_ROOMS) {
    return {
      success: false,
      error: `Server is at full capacity (${MAX_CONCURRENT_ROOMS} rooms). Please wait for a room to close and try again.`,
      code: 'CAPACITY_FULL',
      activeCount,
      maxRooms: MAX_CONCURRENT_ROOMS,
    };
  }

  // Check duplicate: same user + same movieId + same audio (even if audio is empty)
  if (movieId) {
    const duplicate = await checkDuplicateRoom(hostId, movieId, audio || '');
    if (duplicate) {
      return {
        success: false,
        error: `You already have an active room for this content with the same audio track.`,
        code: 'DUPLICATE_ROOM',
        existingRoomId: duplicate.room_id,
      };
    }
  }

  // Generate unique Room ID with collision check
  let roomId = null;
  for (let i = 0; i < MAX_ROOM_ID_RETRIES; i++) {
    const candidate = generateRoomId();
    const exists = await redis.exists(`room:${candidate}`);
    if (!exists) {
      roomId = candidate;
      break;
    }
  }

  if (!roomId) {
    return { success: false, error: 'Unable to create room. Please try again.' };
  }

  const now = Date.now();
  const roomData = {
    host_id: hostId,
    host_name: hostName,
    host_avatar: hostAvatar || '',
    stream_url: streamUrl || '',
    title: title || '',
    movie_id: movieId || '',
    audio: audio || '',
    status: 'WAITING',
    created_at: String(now),
    max_users: String(MAX_USERS),
    current_pos: '0',
    force_sync: 'true',
    has_played: 'false',
  };

  // Create room hash
  await redis.hmset(`room:${roomId}`, roomData);
  await redis.expire(`room:${roomId}`, ROOM_TTL);

  // Host joins only after pressing Enter Room in the lobby.
  return {
    success: true,
    roomId,
    expiresAt: now + ROOM_TTL * 1000,
  };
}

/**
 * Get room info (returns null if room doesn't exist)
 * @param {string} roomId
 * @returns {Object|null}
 */
async function getRoom(roomId) {
  const data = await redis.hgetall(`room:${roomId}`);
  if (!data || Object.keys(data).length === 0) return null;

  const memberCount = await redis.scard(`room:${roomId}:users`);
  const normalized = await normalizeEmptyRoomStatus(roomId, data, memberCount || 0);

  return {
    room_id: roomId,
    host_id: data.host_id,
    host_name: data.host_name,
    stream_url: data.stream_url,
    title: data.title,
    status: normalized?.status || data.status || 'WAITING',
    created_at: parseInt(data.created_at) || 0,
    max_users: parseInt(data.max_users) || MAX_USERS,
    current_pos: parseFloat(data.current_pos) || 0,
    force_sync: data.force_sync === 'true' || data.force_sync === true,
    member_count: memberCount || 0,
    has_played: normalized?.hasPlayed || hasRoomPlayed(data),
    expires_at: (parseInt(data.created_at) || 0) + ROOM_TTL * 1000,
  };
}

/**
 * Delete a room entirely (host ends session)
 * @param {string} roomId
 */
async function deleteRoom(roomId) {
  await redis.del(`room:${roomId}`);
  await redis.del(`room:${roomId}:users`);
  await redis.del(`room:${roomId}:grace`);
}

/**
 * Update room fields
 * @param {string} roomId
 * @param {Object} fields - key-value pairs to update
 */
async function updateRoom(roomId, fields) {
  const stringFields = {};
  for (const [key, value] of Object.entries(fields)) {
    stringFields[key] = String(value);
  }
  await redis.hmset(`room:${roomId}`, stringFields);
}

// ─── User Management ────────────────────────────────────────

/**
 * Atomic join: check capacity + add user (avoids race condition)
 * Since Upstash doesn't support EVAL with Lua, we use SISMEMBER + SCARD + SADD
 * with optimistic approach (acceptable for max 2 users)
 * 
 * @param {string} roomId
 * @param {string} userId
 * @returns {{ success: boolean, reason?: string }}
 */
async function joinRoom(roomId, userId) {
  const roomKey = `room:${roomId}:users`;
  const roomHashKey = `room:${roomId}`;
  const userIdStr = String(userId);

  // Check if user already in room (reconnect case)
  const isMember = await redis.sismember(roomKey, userIdStr);
  if (isMember) {
    return { success: true, reason: 'reconnect' };
  }

  // Check room capacity
  const count = await redis.scard(roomKey);
  const room = await redis.hgetall(roomHashKey);
  const maxUsers = parseInt(room?.max_users) || MAX_USERS;
  const hostId = room?.host_id ? String(room.host_id) : '';
  const isHost = hostId === userIdStr;
  const hostIsMember = hostId ? await redis.sismember(roomKey, hostId) : false;
  const capacityLimit = !isHost && hostId && !hostIsMember
    ? Math.max(0, maxUsers - 1)
    : maxUsers;

  if (count >= capacityLimit) {
    return { success: false, reason: 'Room is full' };
  }

  // Add user
  await redis.sadd(roomKey, userIdStr);
  const roomTtl = await redis.ttl(roomHashKey);
  if (roomTtl > 0) {
    await redis.expire(roomKey, roomTtl);
  }
  return { success: true, reason: 'joined' };
}

/**
 * Remove user from room
 * @param {string} roomId
 * @param {string} userId
 */
async function leaveRoom(roomId, userId) {
  await redis.srem(`room:${roomId}:users`, userId);
  return await normalizeEmptyRoomStatus(roomId);
}

/**
 * Get all members of a room
 * @param {string} roomId
 * @returns {string[]}
 */
async function getRoomMembers(roomId) {
  return await redis.smembers(`room:${roomId}:users`) || [];
}

/**
 * Check if user is host
 * @param {string} roomId
 * @param {string} userId
 * @returns {boolean}
 */
async function isHost(roomId, userId) {
  const hostId = await redis.hget(`room:${roomId}`, 'host_id');
  return hostId === userId;
}

// ─── Grace Period ───────────────────────────────────────────

/**
 * Start grace period for a disconnected user
 * @param {string} roomId
 * @param {string} userId
 */
async function startGracePeriod(roomId, userId) {
  await redis.hset(`room:${roomId}:grace`, userId, String(Date.now()));
}

/**
 * End grace period (user reconnected)
 * @param {string} roomId
 * @param {string} userId
 */
async function endGracePeriod(roomId, userId) {
  await redis.hdel(`room:${roomId}:grace`, userId);
}

/**
 * Check if user is in grace period
 * @param {string} roomId
 * @param {string} userId
 * @returns {boolean}
 */
async function isInGracePeriod(roomId, userId) {
  const timestamp = await redis.hget(`room:${roomId}:grace`, userId);
  return !!timestamp;
}

// ─── Stream Management ──────────────────────────────────────

/**
 * Update stream URL (host only)
 * @param {string} roomId
 * @param {string} streamUrl
 * @param {string} title
 */
async function updateStream(roomId, streamUrl, title) {
  const fields = { stream_url: streamUrl };
  if (title) fields.title = title;
  await updateRoom(roomId, fields);
}

/**
 * Update playback position (host sends every 10s)
 * @param {string} roomId
 * @param {number} positionSec
 */
async function updatePosition(roomId, positionSec) {
  await redis.hset(`room:${roomId}`, 'current_pos', String(positionSec));
}

/**
 * Update room status
 * @param {string} roomId
 * @param {string} status - WAITING | PLAYING | PAUSED | ENDED
 */
async function updateStatus(roomId, status) {
  const updates = { status };
  if (status === 'PLAYING' || status === 'ENDED') {
    updates.has_played = 'true';
  }
  await redis.hmset(`room:${roomId}`, updates);
}

/**
 * Count currently active rooms
 * @returns {number}
 */
async function countActiveRooms() {
  try {
    const allKeys = await redis.keys('room:ROOM-*');
    const roomKeys = allKeys.filter(k => !k.includes(':users') && !k.includes(':grace'));
    return roomKeys.length;
  } catch (error) {
    console.error('countActiveRooms error:', error);
    return 0;
  }
}

/**
 * List all active rooms
 * @returns {Array<Object>} List of active rooms with their info
 */
async function listActiveRooms() {
  try {
    // Get all room keys (excluding :users and :grace subkeys)
    const allKeys = await redis.keys('room:ROOM-*');
    const roomKeys = allKeys.filter(k => !k.includes(':users') && !k.includes(':grace'));

    const rooms = [];
    for (const key of roomKeys) {
      const roomId = key.replace('room:', '');
      const data = await redis.hgetall(key);
      if (!data || !data.host_id) continue;

      const ttl = await redis.ttl(key);
      if (ttl <= 0) continue; // expired or no TTL

      const members = await redis.smembers(`room:${roomId}:users`);
      const normalized = await normalizeEmptyRoomStatus(roomId, data, members ? members.length : 0);

      rooms.push({
        room_id: roomId,
        title: data.title || '',
        host_id: data.host_id,
        host_name: data.host_name || 'Host',
        host_avatar: data.host_avatar || '',
        status: normalized?.status || data.status || 'WAITING',
        member_count: members ? members.length : 0,
        max_users: parseInt(data.max_users) || MAX_USERS,
        created_at: parseInt(data.created_at) || 0,
        ttl_seconds: ttl,
      });
    }

    // Sort by newest first
    rooms.sort((a, b) => b.created_at - a.created_at);
    return rooms;
  } catch (error) {
    console.error('listActiveRooms error:', error);
    return [];
  }
}

/**
 * Check if a user already has a room with the same movie_id + audio
 * @param {string|object} hostId
 * @param {string|number} movieId
 * @param {string} audio - 'vietsub' | 'dubbed' | ''
 * @returns {Object|null} existing room or null
 */
async function checkDuplicateRoom(hostId, movieId, audio) {
  try {
    const allKeys = await redis.keys('room:ROOM-*');
    const roomKeys = allKeys.filter(k => !k.includes(':users') && !k.includes(':grace'));

    const hostIdStr = String(hostId);
    const movieIdStr = String(movieId);
    const audioStr = String(audio || '');

    for (const key of roomKeys) {
      const data = await redis.hgetall(key);
      if (!data || !data.host_id) continue;

      if (
        String(data.host_id) === hostIdStr &&
        String(data.movie_id) === movieIdStr &&
        String(data.audio || '') === audioStr
      ) {
        const roomId = key.replace('room:', '');
        return {
          room_id: roomId,
          title: data.title || '',
          audio: data.audio || '',
        };
      }
    }
    return null;
  } catch (error) {
    console.error('checkDuplicateRoom error:', error);
    return null;
  }
}

module.exports = {
  createRoom,
  getRoom,
  deleteRoom,
  updateRoom,
  joinRoom,
  leaveRoom,
  normalizeEmptyRoomStatus,
  getRoomMembers,
  isHost,
  startGracePeriod,
  endGracePeriod,
  isInGracePeriod,
  updateStream,
  updatePosition,
  updateStatus,
  listActiveRooms,
  countActiveRooms,
  checkDuplicateRoom,
  isValidStreamUrl,
  ROOM_TTL,
  MAX_USERS,
  MAX_CONCURRENT_ROOMS,
};
