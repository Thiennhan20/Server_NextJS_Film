<div align="center">

# 🔧 MovieSaw Backend — RESTful API & Real-time Server

<img src="https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="Node.js" />
<img src="https://img.shields.io/badge/Express-4.18-000000?style=for-the-badge&logo=express&logoColor=white" alt="Express" />
<img src="https://img.shields.io/badge/MongoDB-8-47A248?style=for-the-badge&logo=mongodb&logoColor=white" alt="MongoDB" />
<img src="https://img.shields.io/badge/Redis-Caching-DC382D?style=for-the-badge&logo=redis&logoColor=white" alt="Redis" />
<img src="https://img.shields.io/badge/Socket.IO-Real_Time-010101?style=for-the-badge&logo=socketdotio&logoColor=white" alt="Socket.IO" />
<img src="https://img.shields.io/badge/JWT-Auth-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white" alt="JWT" />
<img src="https://img.shields.io/badge/Render-Deployed-46E3B7?style=for-the-badge&logo=render&logoColor=white" alt="Render" />

<br />

**Production-ready backend powering the MovieSaw streaming platform.**

**Handles authentication, user data, comments, watch progress, and real-time communication.**

<br />

[🌐 API Server](https://server-nextjs-film.onrender.com) · [🎬 Frontend Repo](https://github.com/) · [📧 Contact](mailto:nhanntn2203@gmail.com)

<br />
  
</div>

---

## ✨ Core Features

<table>
<tr>
<td width="50%">

### 🔐 Authentication & Security
- **JWT** access + refresh token rotation
- **Google OAuth 2.0** social login
- **Email verification** via Brevo transactional email
- **Password hashing** with bcrypt (salt rounds)
- **Rate limiting** per IP & per user
- **Helmet** security headers
- **CORS** whitelist configuration
- **CSRF** protection
- **Token blacklisting** on logout

</td>
<td width="50%">

### 💾 Data & Caching
- **MongoDB** with Mongoose ODM
- **Redis** (Upstash) for high-speed caching
- **Node-Cache** in-memory fallback
- **TMDB API proxy** with response caching
- **Image proxy** with Sharp optimization
- **Compression** middleware (gzip/brotli)

</td>
</tr>
<tr>
<td width="50%">

### 💬 Real-time Features
- **WebSocket** server via Socket.IO
- **Live chat rooms** for streaming
- **User presence** tracking (online/offline)
- **System messages** (join/leave notifications)
- **Image messages** support in chat

</td>
<td width="50%">

### 📊 User Data Management
- **Watch progress** sync across devices
- **Watchlist** with cloud persistence
- **Comments** with likes, replies & nested threads
- **User profiles** with avatar upload
- **Admin panel** endpoints

</td>
</tr>
</table>

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                  EXPRESS SERVER                      │
│                                                     │
│  ┌─────────────┐   ┌─────────────┐   ┌──────────┐  │
│  │  Middleware  │   │   Routes    │   │ WebSocket│  │
│  │             │   │             │   │          │  │
│  │ • Auth JWT  │   │ • /auth     │   │ • Chat   │  │
│  │ • Rate Limit│   │ • /comments │   │ • Users  │  │
│  │ • Helmet    │   │ • /recently │   │ • Events │  │
│  │ • CORS      │   │ • /tmdb     │   │          │  │
│  │ • Compress  │   │ • /avatar   │   │          │  │
│  └──────┬──────┘   └──────┬──────┘   └─────┬────┘  │
│         │                 │                │       │
│  ┌──────┴─────────────────┴────────────────┴────┐  │
│  │               Data Layer                     │  │
│  └──────┬──────────────┬───────────────┬────────┘  │
└─────────┼──────────────┼───────────────┼───────────┘
          ▼              ▼               ▼
   ┌──────────┐   ┌──────────┐   ┌──────────────┐
   │ MongoDB  │   │  Redis   │   │   External   │
   │ Atlas    │   │ (Upstash)│   │   APIs       │
   │          │   │          │   │              │
   │ • Users  │   │ • Cache  │   │ • TMDB       │
   │ • Comment│   │ • Session│   │ • Brevo Mail │
   │ • Watch  │   │ • Rate   │   │ • Google     │
   │   Progress│  │   Limit  │   │   OAuth      │
   └──────────┘   └──────────┘   └──────────────┘
```

---

## 🛠️ Tech Stack

| Category | Technologies |
|:---|:---|
| **Runtime** | Node.js 18+ |
| **Framework** | Express.js 4.18 |
| **Database** | MongoDB 6 + Mongoose 8 ODM |
| **Caching** | Redis (Upstash) + Node-Cache (fallback) |
| **Real-time** | Socket.IO 4.8 |
| **Auth** | JWT (jsonwebtoken) + Google Auth Library |
| **Email** | Brevo SDK + Nodemailer |
| **Security** | Helmet, CORS, CSRF, bcrypt, Rate Limiter |
| **Image Processing** | Sharp |
| **HTTP** | Axios |
| **Logging** | Winston |
| **Deployment** | Render (Web Service) |

---

## 📁 Project Structure

```
server-en-website/
├── server.js               # Express app entry point
├── websocket.js            # Socket.IO configuration
├── middleware/
│   └── auth.js             # JWT verification middleware
├── routes/
│   ├── auth.js             # Register, Login, Verify, Google OAuth
│   ├── comments.js         # CRUD comments with likes & replies
│   ├── recentlyWatched.js  # Watch progress sync
│   ├── tmdb.js             # TMDB API proxy with caching
│   └── avatarProxy.js      # Avatar image proxy
├── models/
│   ├── User.js             # User schema (profile, roles, prefs)
│   ├── Comment.js          # Comment schema (nested, likes)
│   ├── WatchProgress.js    # Watch progress schema
│   └── BlacklistedToken.js # Revoked JWT tokens
├── config/                 # Database & service configs
├── utils/                  # Helper functions
└── scripts/                # Maintenance scripts
```

---

## 🔌 API Endpoints

### 🔐 Authentication

| Method | Endpoint | Description |
|:---|:---|:---|
| `POST` | `/auth/register` | Register with email & password |
| `POST` | `/auth/login` | Login, returns JWT access + refresh tokens |
| `POST` | `/auth/google` | Google OAuth login/register |
| `POST` | `/auth/refresh-token` | Rotate refresh token |
| `POST` | `/auth/logout` | Blacklist current token |
| `GET` | `/auth/verify-email/:token` | Verify email address |
| `GET` | `/auth/me` | Get current user profile |
| `PUT` | `/auth/profile` | Update profile (name, avatar) |

### 💬 Comments

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/comments/:movieId` | Get comments for a movie/show |
| `POST` | `/comments` | Create a new comment |
| `POST` | `/comments/:id/reply` | Reply to a comment |
| `PUT` | `/comments/:id/like` | Toggle like on a comment |
| `DELETE` | `/comments/:id` | Delete own comment |

### 📺 Watch Progress

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/recently-watched` | Get user's watch history |
| `POST` | `/recently-watched` | Save/update watch progress |
| `DELETE` | `/recently-watched/:id` | Remove from history |

### 🔌 WebSocket Events

| Direction | Event | Payload |
|:---|:---|:---|
| `Client → Server` | `user_join` | `{ username }` |
| `Client → Server` | `chat_message` | `{ content }` |
| `Client → Server` | `image_message` | `{ imageData }` |
| `Server → Client` | `chat_message` | `{ type, username, content, timestamp }` |
| `Server → Client` | `user_list` | `[{ username, ... }]` |

---

## 🚀 Getting Started

### Prerequisites

- **Node.js** ≥ 18
- **MongoDB** (Atlas or local)
- **Redis** (Upstash recommended for free tier)

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd server-en-website

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your credentials
```

### Environment Variables

```env
PORT=3001
MONGODB_URI=               # MongoDB connection string
JWT_SECRET=                # JWT signing secret
JWT_REFRESH_SECRET=        # Refresh token secret
GOOGLE_CLIENT_ID=          # Google OAuth client ID
GOOGLE_CLIENT_SECRET=      # Google OAuth web client secret
GOOGLE_REDIRECT_BASE_URL=  # Public API origin, for example https://api.example.com
BREVO_API_KEY=             # Brevo transactional email
UPSTASH_REDIS_URL=         # Redis connection URL
TMDB_API_KEY=              # TMDB API key
CLIENT_URL=                # Frontend URL (CORS)
```

### Google Login For The Mobile App

The Expo app starts Google sign-in through `GET /api/auth/google/mobile`; the
server owns the Google client secret and redirects the completed session back
to the app. In Google Cloud Console, add this authorized redirect URI exactly:

```text
<GOOGLE_REDIRECT_BASE_URL>/api/auth/google/mobile-callback
```

For production, `GOOGLE_REDIRECT_BASE_URL` must be the public HTTPS origin of
this server. The app does not need Google client secrets or client IDs.

### Development

```bash
# Start with auto-reload (Node --watch)
npm run dev

# Start production
npm start
```

Server runs on `http://localhost:3001` by default.

---

## 🔒 Security Features

| Feature | Implementation |
|:---|:---|
| 🔑 Password Hashing | bcrypt with configurable salt rounds |
| 🎫 Token Management | JWT access (15min) + refresh (7d) rotation |
| 🚫 Token Blacklist | Revoked tokens stored in MongoDB |
| 🛡️ Rate Limiting | Per-IP and per-user with rate-limiter-flexible |
| 🔒 Security Headers | Helmet.js with strict CSP |
| 🌐 CORS | Whitelist-based origin control |
| ✅ Input Validation | express-validator on all endpoints |
| 📧 Email Verification | Required before full account access |

---

## 🔗 Related

- [Frontend Client Repository](https://github.com/) — Next.js 15 with 3D visuals & streaming UI
- [Live Application](https://moviesaw.vercel.app/)
- [API Server](https://server-nextjs-film.onrender.com)

---

<div align="center">

**Built with ❤️ using Node.js, Express, and MongoDB**

<img src="https://img.shields.io/badge/Made_with-Node.js-339933?style=flat-square&logo=nodedotjs" />
<img src="https://img.shields.io/badge/Deployed_on-Render-46E3B7?style=flat-square&logo=render" />

</div>
