/**
 * Centralized CORS configuration for Express HTTP server and Socket.IO WebSocket
 */

const defaultOrigins = [
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:3002',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:3001',
  'http://127.0.0.1:3002',
  'https://moviesaw.vercel.app',
  'https://enterntn.duckdns.org',
  'https://www.enterntn.duckdns.org',
  'https://ntngame.fly.dev'
];

// Append process.env.CLIENT_URL if provided
if (process.env.CLIENT_URL) {
  const envUrls = process.env.CLIENT_URL.split(',').map(url => url.trim().replace(/\/+$/, ''));
  envUrls.forEach(url => {
    if (url && !defaultOrigins.includes(url)) {
      defaultOrigins.push(url);
    }
  });
}

// Generate normalized array (both without and with trailing slash for maximum compatibility)
const allowedOrigins = Array.from(
  new Set([
    ...defaultOrigins,
    ...defaultOrigins.map(url => `${url}/`)
  ])
);

const corsOptions = {
  origin: allowedOrigins,
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

module.exports = {
  allowedOrigins,
  corsOptions
};
