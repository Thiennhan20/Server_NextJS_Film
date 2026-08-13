const express = require('express');
const http = require('http');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const compression = require('compression');
const mongoose = require('mongoose');
const axios = require('axios');
require('dotenv').config();

const initializeWebSocket = require('./websocket');
const authRoutes = require('./routes/auth');
const commentRoutes = require('./routes/comments');
const recentlyWatchedRoutes = require('./routes/recentlyWatched');
const avatarProxyRoutes = require('./routes/avatarProxy');
const tmdbRoutes = require('./routes/tmdb');
const chatAIRoutes = require('./routes/chatAI');
const server3Routes = require('./routes/nguonc');
const server1Routes = require('./routes/phimapi');
const roomRoutes = require('./routes/rooms');
const searchHistoryRoutes = require('./routes/searchHistory');
const notificationRoutes = require('./routes/notifications');
const friendsRoutes = require('./routes/friends');

const app = express();
// Security middleware
app.use(helmet({
  crossOriginEmbedderPolicy: false, // Tắt để tương thích Safari
  crossOriginOpenerPolicy: false,
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      frameSrc: ["'self'", "https://vidsrc.icu", "https://www.youtube.com", "https://*.streamc.xyz", "https://embed.streamc.xyz", "https://phim.nguonc.com", "https://*.nguonc.com"],
    },
  },
}));
app.disable('x-powered-by');

// Enable response compression
app.use(compression());
app.use(cookieParser());

// CORS configuration
const corsOptions = {
  origin: [
    process.env.CLIENT_URL || 'http://localhost:3000',
    'https://moviesaw.vercel.app',
    'https://moviesaw.vercel.app/',
    'https://enterntn.duckdns.org',
    'https://enterntn.duckdns.org/',
    'https://www.enterntn.duckdns.org',
    'https://www.enterntn.duckdns.org/',
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:3002',
    'http://localhost:3002/',
    'https://ntngame.fly.dev',
    'https://ntngame.fly.dev/'
  ],
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};
app.use(cors(corsOptions));
// Increase body size limit for avatar uploads (base64 images)
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ limit: '15mb', extended: true }));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
  .then(async () => {
    console.log('✅ Connected to MongoDB');
    try {
      const WatchProgress = require('./models/WatchProgress');
      await WatchProgress.syncIndexes();
    } catch {
      // Sync indexes silently in background
    }
  })
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// MongoDB event handlers
mongoose.connection.on('disconnected', () => {
  console.warn('⚠️ MongoDB disconnected. Attempting to reconnect...');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconnected');
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/comments', commentRoutes);
app.use('/api/recently-watched', recentlyWatchedRoutes);
app.use('/api/avatar', avatarProxyRoutes);
app.use('/api/tmdb', tmdbRoutes);
app.use('/api/chatai', chatAIRoutes);
app.use('/api/server3', server3Routes);
app.use('/api/server1', server1Routes);
app.use('/api/rooms', roomRoutes);
app.use('/api/search-history', searchHistoryRoutes);
app.use('/api/notifications', notificationRoutes);
app.use('/api/friends', friendsRoutes);

// Tạo HTTP server
const server = http.createServer(app);

// Khởi tạo WebSocket và lưu io instance để routes có thể emit events
const io = initializeWebSocket(server);
app.set('io', io);

// Route cơ bản để kiểm tra server
app.get('/', (req, res) => {
  res.send(`
  <!DOCTYPE html>
  <html lang="vi">
  <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>NHAN</title>
      <style>
          body {
              margin: 0;
              font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
              background: linear-gradient(135deg, #1e3c72, #2a5298);
              display: flex;
              justify-content: center;
              align-items: center;
              height: 100vh;
              color: white;
          }

          .card {
              background: rgba(255, 255, 255, 0.1);
              backdrop-filter: blur(10px);
              padding: 40px;
              border-radius: 16px;
              text-align: center;
              box-shadow: 0 10px 30px rgba(0,0,0,0.3);
              width: 400px;
          }

          h1 {
              margin-bottom: 10px;
              font-size: 28px;
          }

          h2 {
              margin-top: 0;
              font-weight: 400;
              font-size: 18px;
              opacity: 0.9;
          }

          .info {
              margin-top: 25px;
              font-size: 16px;
              line-height: 1.8;
          }

          .badge {
              display: inline-block;
              padding: 6px 12px;
              margin-top: 15px;
              border-radius: 20px;
              background: #00c6ff;
              color: #000;
              font-weight: bold;
              font-size: 14px;
          }

          .footer {
              margin-top: 20px;
              font-size: 13px;
              opacity: 0.7;
          }
      </style>
  </head>
  <body>
      <div class="card">
          <h1>🚀Server</h1>

          <div class="badge">Server Status: ONLINE ✅</div>

          <div class="info">
              📧 Email: <strong>nhanntn2203@gmail.com</strong><br/>
              📱 Phone: <strong>0388 875 120</strong><br/>
          </div>

          <div class="footer">
              © ${new Date().getFullYear()} NHAN. All rights reserved.
          </div>
      </div>
  </body>
  </html>
  `);
});

// Lấy trạng thái của server
app.get('/health', async (req, res) => {
  const start = Date.now();
  try {
    // Thực hiện truy vấn đơn giản tới database
    await mongoose.connection.db.admin().ping();
    const dbLatency = Date.now() - start; // ms
    res.status(200).json({
      status: 'OK',
      db: 'connected',
      dbLatency: dbLatency + 'ms'
    });
  } catch (err) {
    const dbLatency = Date.now() - start;
    res.status(500).json({
      status: 'ERROR',
      db: 'disconnected',
      dbLatency: dbLatency + 'ms'
    });
  }
});


// Kiểm tra địa chỉ IP và vị trí mạng của server
app.get('/ip-info', async (req, res) => {
  try {
    const ipRes = await axios.get('http://ip-api.com/json', { timeout: 5000 });
    res.json({
      ip: ipRes.data.query,
      city: ipRes.data.city,
      region: ipRes.data.regionName,
      country: ipRes.data.country,
      isp: ipRes.data.isp,
      org: ipRes.data.org
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`
    ╔════════════════════════════════════════════════════════╗
    ║         🔒 SECURE STREAM SERVER v1.0.0                 ║
    ╠════════════════════════════════════════════════════════╣
    ║  Port:        ${PORT}                                     ║
    ║  Encryption:  AES-256-GCM                              ║
    ║  CORS:                                                 ║
    ║  Rate Limit:                                           ║
    ╚════════════════════════════════════════════════════════╝
    `);

  // Log outbound network IP & location
  axios.get('http://ip-api.com/json', { timeout: 5000 })
    .then(r => {
      console.log(`🌐 Server Outbound IP: ${r.data.query} (${r.data.city || ''}, ${r.data.country || ''} - ISP: ${r.data.isp || r.data.org || ''})`);
    })
    .catch(err => {
      console.log('🌐 Could not fetch public IP:', err.message);
    });
}); 
