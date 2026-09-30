const { Redis } = require('@upstash/redis');

// Upstash Redis client (for Vercel/Serverless)
const upstashRedis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

// Traditional Redis client (for local development with ioredis)
let ioRedisClient = null;

if (process.env.NODE_ENV === 'development' && process.env.REDIS_URL) {
  const IORedis = require('ioredis');
  ioRedisClient = new IORedis(process.env.REDIS_URL);
  
  ioRedisClient.on('connect', () => {
    console.log('✅ Connected to local Redis');
  });
  
  ioRedisClient.on('error', (err) => {
    console.error('❌ Redis connection error:', err);
  });
}

// Unified Redis interface
const redisClient = {
  // Get value
  async get(key) {
    try {
      let raw;
      if (ioRedisClient) {
        raw = await ioRedisClient.get(key);
      } else {
        raw = await upstashRedis.get(key);
      }
      if (raw === null || raw === undefined) return null;
      // Auto-parse if value is returned as JSON string
      if (typeof raw === 'string') {
        try {
          return JSON.parse(raw);
        } catch {
          return raw;
        }
      }
      return raw;
    } catch (error) {
      console.error('Redis GET error:', error);
      return null;
    }
  },

  // Set value with optional expiration (seconds)
  async set(key, value, expirationSeconds = null) {
    try {
      if (ioRedisClient) {
        const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
        if (expirationSeconds) {
          return await ioRedisClient.setex(key, expirationSeconds, stringValue);
        }
        return await ioRedisClient.set(key, stringValue);
      }
      
      // Upstash Redis automatically handles JSON serialization
      if (expirationSeconds) {
        return await upstashRedis.set(key, value, { ex: expirationSeconds });
      }
      return await upstashRedis.set(key, value);
    } catch (error) {
      console.error('Redis SET error:', error);
      return null;
    }
  },

  // Delete key(s)
  async del(...keys) {
    try {
      if (keys.length === 0) return 0;
      const flatKeys = keys.flat();
      if (flatKeys.length === 0) return 0;

      if (ioRedisClient) {
        return await ioRedisClient.del(...flatKeys);
      }
      return await upstashRedis.del(...flatKeys);
    } catch (error) {
      console.error('Redis DEL error:', error);
      return null;
    }
  },

  // Check if key exists
  async exists(key) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.exists(key);
      }
      return await upstashRedis.exists(key);
    } catch (error) {
      console.error('Redis EXISTS error:', error);
      return 0;
    }
  },

  // Set expiration on existing key
  async expire(key, seconds) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.expire(key, seconds);
      }
      return await upstashRedis.expire(key, seconds);
    } catch (error) {
      console.error('Redis EXPIRE error:', error);
      return 0;
    }
  },

  // Get remaining TTL of a key (seconds)
  async ttl(key) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.ttl(key);
      }
      return await upstashRedis.ttl(key);
    } catch (error) {
      console.error('Redis TTL error:', error);
      return -2;
    }
  },

  // Get all keys matching pattern
  async keys(pattern) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.keys(pattern);
      }
      return await upstashRedis.keys(pattern);
    } catch (error) {
      console.error('Redis KEYS error:', error);
      return [];
    }
  },

  // Hash operations
  async hset(key, field, value) {
    try {
      const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
      if (ioRedisClient) {
        return await ioRedisClient.hset(key, field, stringValue);
      }
      return await upstashRedis.hset(key, { [field]: stringValue });
    } catch (error) {
      console.error('Redis HSET error:', error);
      return null;
    }
  },

  async hget(key, field) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.hget(key, field);
      }
      return await upstashRedis.hget(key, field);
    } catch (error) {
      console.error('Redis HGET error:', error);
      return null;
    }
  },

  async hgetall(key) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.hgetall(key);
      }
      return await upstashRedis.hgetall(key);
    } catch (error) {
      console.error('Redis HGETALL error:', error);
      return {};
    }
  },

  async hdel(key, field) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.hdel(key, field);
      }
      return await upstashRedis.hdel(key, field);
    } catch (error) {
      console.error('Redis HDEL error:', error);
      return null;
    }
  },

  // Increment
  async incr(key) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.incr(key);
      }
      return await upstashRedis.incr(key);
    } catch (error) {
      console.error('Redis INCR error:', error);
      return null;
    }
  },

  // Set multi-field hash
  async hmset(key, obj) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.hmset(key, obj);
      }
      // Upstash hset accepts object directly
      return await upstashRedis.hset(key, obj);
    } catch (error) {
      console.error('Redis HMSET error:', error);
      return null;
    }
  },

  // Set: Add member
  async sadd(key, ...members) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.sadd(key, ...members);
      }
      return await upstashRedis.sadd(key, ...members);
    } catch (error) {
      console.error('Redis SADD error:', error);
      return null;
    }
  },

  // Set: Remove member
  async srem(key, ...members) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.srem(key, ...members);
      }
      return await upstashRedis.srem(key, ...members);
    } catch (error) {
      console.error('Redis SREM error:', error);
      return null;
    }
  },

  // Set: Count members
  async scard(key) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.scard(key);
      }
      return await upstashRedis.scard(key);
    } catch (error) {
      console.error('Redis SCARD error:', error);
      return 0;
    }
  },

  // Set: Check if member exists
  async sismember(key, member) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.sismember(key, member);
      }
      return await upstashRedis.sismember(key, member);
    } catch (error) {
      console.error('Redis SISMEMBER error:', error);
      return 0;
    }
  },

  // Set: Get all members
  async smembers(key) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.smembers(key);
      }
      return await upstashRedis.smembers(key);
    } catch (error) {
      console.error('Redis SMEMBERS error:', error);
      return [];
    }
  },

  // Decrement
  async decr(key) {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.decr(key);
      }
      return await upstashRedis.decr(key);
    } catch (error) {
      console.error('Redis DECR error:', error);
      return null;
    }
  },

  // Ping
  async ping() {
    try {
      if (ioRedisClient) {
        return await ioRedisClient.ping();
      }
      return await upstashRedis.ping();
    } catch (error) {
      console.error('Redis PING error:', error);
      return null;
    }
  },

  // Close connection (for local Redis)
  async quit() {
    if (ioRedisClient) {
      await ioRedisClient.quit();
    }
  }
};

module.exports = redisClient;
