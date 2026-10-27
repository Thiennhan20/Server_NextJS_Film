const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Cấu hình DUY NHẤT model gemini-3.7-flash (không tự chuyển sang model khác)
const TARGET_MODEL = 'gemini-3.7-flash';
const VERTEX_MODELS = [TARGET_MODEL];

const DEFAULT_LOCATION = process.env.VERTEX_LOCATION || 'us-central1';

// Prompt hệ thống nghiêm ngặt: CHỈ hỗ trợ điện ảnh, phim ảnh
const MOVIE_AI_SYSTEM_INSTRUCTION = `Bạn là Trợ lý Điện ảnh AI thông minh của nền tảng phim NTN Stream (MovieWorld).
Bạn có kiến thức sâu rộng và khả năng tra cứu Google Search thời gian thực về toàn bộ thế giới điện ảnh: Hollywood, Châu Á, Phim Chiếu Rạp, Phim Bộ, Phim Lẻ, Hoạt hình/Anime từ các nguồn dữ liệu TMDB, NguonC, KKPhim.

BẮT BUỘC TUÂN THỦ CÁC QUY TẮC BẢO MẬT VÀ PHẠM VI (STRICT GUARDRAIL):
1. PHẠM VI HỖ TRỢ DUY NHẤT:
   - Bạn CHỈ ĐƯỢC PHÉP trả lời, tư vấn, tìm kiếm và gợi ý các nội dung liên quan trực tiếp đến:
     + Phim ảnh (phim lẻ, phim bộ, anime, tài liệu, phim chiếu rạp).
     + Diễn viên, đạo diễn, nhà sản xuất, giải thưởng điện ảnh (Oscar, Quả Cầu Vàng, Cannes...).
     + Thể loại phim, review/tóm tắt nội dung phim (TUYỆT ĐỐI KHÔNG spoil tình tiết bất ngờ hoặc cái kết trừ khi người dùng yêu cầu).
     + Gợi ý phim theo tâm trạng, sở thích, ngày lễ hoặc theo chủ đề (du hành thời gian, tình cảm, trinh thám, kinh dị...).
     + Trải nghiệm xem phim và các tính năng giải trí trên website NTN Stream.

2. QUY TẮC TỪ CHỐI CÁC CHỦ ĐỀ NGOÀI ĐIỆN ẢNH:
   - Nếu người dùng hỏi bất kỳ chủ đề nào KHÔNG liên quan đến phim ảnh (ví dụ: giải toán, viết code lập trình, tin học, chính trị, tôn giáo, y tế, chứng khoán, bài tập về nhà, v.v.):
     BẠN PHẢI TỪ CHỐI LỊCH SỰ bằng tiếng Việt theo mẫu:
     "Xin lỗi bạn, tôi là trợ lý AI chuyên về phim ảnh của NTN Stream. Tôi chỉ có thể hỗ trợ các thông tin về phim ảnh, diễn viên, đạo diễn và gợi ý phim thôi nhé! 🎬🍿\nHôm nay bạn muốn tìm hoặc xem phim thuộc thể loại gì nào?"

3. TỰ ĐỘNG CẬP NHẬT GOOGLE SEARCH THỜI GIAN THỰC:
   - Luôn sử dụng Google Search để kiểm tra các thông tin mới nhất: tên chính thức của các phần phim mới (ví dụ: Avatar 3 tên chính thức là "Avatar: Fire and Ash"), ngày ra mắt, trạng thái trailer, dàn diễn viên. Tuyệt đối không dùng thông tin cũ đã lỗi thời.

4. HÌNH ẢNH POSTER VÀ LINK XEM PHIM TRÊN NTN STREAM:
   - Bạn HOÀN TOÀN ĐƯỢC PHÉP và NÊN chèn hình ảnh poster phim bằng Markdown: ![Tên Phim](URL_HÌNH_ẢNH) (lấy từ kết quả tìm kiếm Google, TMDB: https://image.tmdb.org/t/p/w500/..., hoặc ảnh poster chính thức). Tuyệt đối KHÔNG nói rằng "tôi là mô hình ngôn ngữ không thể hiển thị hình ảnh".
   - Khi người dùng hỏi tìm phim hoặc xin link xem:
     + Nếu phim có trên hệ thống hoặc đã phát hành, hãy cung cấp link xem trực tiếp trên NTN Stream:
       [🎬 Xem phim trên NTN Stream](/search?q=Tên+Phim) (hoặc [🎬 Xem ngay](/movies/ID) nếu biết ID TMDB).
     + Nếu phim chưa phát hành (như các phần phim sắp ra rạp): Hãy nêu rõ ngày ra rạp chính thức và gửi link theo dõi:
       [🎬 Theo dõi phim trên NTN Stream](/search?q=Tên+Phim).
     + Tuyệt đối KHÔNG nói "tôi không có link", mà hãy tạo link tìm kiếm/xem trực tiếp trên NTN Stream!

5. CÂU HỎI VỀ TÁC GIẢ HOẶC NGƯỜI TẠO RA WEB:
   - Nếu người dùng hỏi ai tạo ra trang web này, tác giả là ai:
     Trả lời: "Website NTN Stream được sáng lập và phát triển bởi Nguyễn Thiện Nhân (22 tuổi) 🚀."

6. ĐỊNH DẠNG VÀ PHONG CÁCH TRẢ LỜI:
   - Sử dụng Markdown rõ ràng: in đậm tên phim, gạch đầu dòng các gợi ý.
   - Khi gợi ý phim, luôn nêu: **Tên Phim** (Năm phát hành) - Thể loại - Điểm đánh giá (nếu có) kèm 1-2 câu tóm tắt cuốn hút.
   - Giọng điệu thân thiện, hào hứng, yêu điện ảnh, dùng các icon phù hợp (🎬, 🍿, ⭐, ✨).`;

let cachedCredentials = null;
let cachedToken = null;
let tokenExpiresAt = 0;

/**
 * Tự động tìm nạp Service Account Key từ nhiều nguồn:
 * 1. Biến môi trường GCP_SERVICE_ACCOUNT_KEY (trên Render hoặc local .env)
 * 2. Secret File của Render (/etc/secrets/...)
 * 3. Thư mục credentials local (d:/Cursor/credentials/...)
 */
function loadCredentials() {
  if (cachedCredentials) return cachedCredentials;

  // 1. Biến môi trường GCP_SERVICE_ACCOUNT_KEY (Render Env Var)
  if (process.env.GCP_SERVICE_ACCOUNT_KEY) {
    try {
      const raw = process.env.GCP_SERVICE_ACCOUNT_KEY.trim();
      const jsonStr = raw.startsWith('{') ? raw : Buffer.from(raw, 'base64').toString('utf8');
      cachedCredentials = JSON.parse(jsonStr);
      console.log('✅ [VertexAI] Nạp credentials thành công từ GCP_SERVICE_ACCOUNT_KEY env');
      return cachedCredentials;
    } catch (err) {
      console.warn('⚠️ [VertexAI] Lỗi parse GCP_SERVICE_ACCOUNT_KEY:', err.message);
    }
  }

  // 2. Danh sách các đường dẫn candidate (Render Secret File + Local paths)
  const candidatePaths = [
    '/etc/secrets/gen-lang-client.json',
    '/etc/secrets/gen-lang-client-0182514549-78da1d6f0f86.json',
    '/etc/secrets/google-credentials.json',
    '/etc/secrets/credentials.json',
    path.resolve(__dirname, '../../credentials/gen-lang-client-0182514549-78da1d6f0f86.json'),
    path.resolve(__dirname, '../credentials/gen-lang-client-0182514549-78da1d6f0f86.json'),
    'd:/Cursor/credentials/gen-lang-client-0182514549-78da1d6f0f86.json',
    'D:/Cursor/credentials/gen-lang-client-0182514549-78da1d6f0f86.json'
  ];

  // Quét toàn bộ file .json trong /etc/secrets/ trên Render nếu có
  try {
    const renderSecretDir = '/etc/secrets';
    if (fs.existsSync(renderSecretDir)) {
      const files = fs.readdirSync(renderSecretDir).filter(f => f.endsWith('.json'));
      for (const f of files) {
        candidatePaths.unshift(path.join(renderSecretDir, f));
      }
    }
  } catch {}

  // Quét thêm bất kỳ file .json nào trong folder credentials nếu có
  try {
    const credDir = path.resolve(__dirname, '../../credentials');
    if (fs.existsSync(credDir)) {
      const files = fs.readdirSync(credDir).filter(f => f.endsWith('.json'));
      for (const f of files) {
        candidatePaths.push(path.join(credDir, f));
      }
    }
  } catch {}

  for (const p of candidatePaths) {
    try {
      if (fs.existsSync(p)) {
        const raw = fs.readFileSync(p, 'utf8');
        cachedCredentials = JSON.parse(raw);
        console.log(`✅ [VertexAI] Nạp credentials thành công từ file: ${p}`);
        return cachedCredentials;
      }
    } catch {}
  }

  return null;
}

/**
 * Tạo Signed JWT Bearer token từ RSA Private Key (chuẩn OAuth2 Service Account)
 */
function createJWT(creds) {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const claimSet = Buffer.from(JSON.stringify({
    iss: creds.client_email,
    scope: 'https://www.googleapis.com/auth/cloud-platform',
    aud: creds.token_uri || 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now
  })).toString('base64url');

  const sign = crypto.createSign('RSA-SHA256');
  sign.update(`${header}.${claimSet}`);
  const signature = sign.sign(creds.private_key, 'base64url');

  return `${header}.${claimSet}.${signature}`;
}

/**
 * Lấy Access Token Google Cloud với in-memory cache tự động làm mới
 */
async function getAccessToken() {
  const now = Date.now();
  if (cachedToken && tokenExpiresAt > now + 60000) {
    return cachedToken;
  }

  const creds = loadCredentials();
  if (!creds || !creds.client_email || !creds.private_key) {
    throw new Error('Google Cloud Service Account credentials không tìm thấy hoặc không hợp lệ');
  }

  const jwt = createJWT(creds);
  const tokenUri = creds.token_uri || 'https://oauth2.googleapis.com/token';

  const res = await fetch(tokenUri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });

  const data = await res.json();
  if (!res.ok || !data.access_token) {
    throw new Error(`Lỗi cấp phát OAuth2 token từ Google: ${data.error_description || data.error || res.statusText}`);
  }

  cachedToken = data.access_token;
  tokenExpiresAt = now + ((data.expires_in || 3600) * 1000);
  return cachedToken;
}

/**
 * Kiểm tra xem Vertex AI đã sẵn sàng hoạt động hay chưa
 */
function isConfigured() {
  return !!loadCredentials() || !!process.env.GEMINI_API_KEY;
}

/**
 * Gọi Google Generative Language API với DUY NHẤT model gemini-3.7-flash
 */
async function callGenerativeLanguageApi(formattedContents, systemPromptText, stream = false) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY không được tìm thấy trên Server');
  }

  const action = stream ? 'streamGenerateContent?alt=sse&' : 'generateContent?';
  const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${TARGET_MODEL}:${action}key=${apiKey}`;

  const payload = {
    systemInstruction: { parts: [{ text: systemPromptText }] },
    contents: formattedContents,
    generationConfig: {
      temperature: 0.7,
      maxOutputTokens: 4096,
      topP: 0.95
    }
  };

  let lastErr = null;
  // Thử tối đa 2 lần với chính gemini-3.7-flash (phòng trường hợp 503 tạm thời)
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errText = await response.text();
        if (response.status === 503 && attempt < 2) {
          console.warn(`⚠️ [Gemini 3.7 Flash] Gặp 503 tạm thời, đang thử lại lần ${attempt + 1}...`);
          await new Promise(r => setTimeout(r, 1500));
          continue;
        }
        throw new Error(`GenerativeLanguage API status ${response.status}: ${errText}`);
      }

      if (stream) {
        return response.body;
      }

      const data = await response.json();
      const parts = data.candidates?.[0]?.content?.parts || [];
      const text = parts
        .filter(p => p.text && !p.thought)
        .map(p => p.text)
        .join('');

      if (!text) {
        throw new Error('Mô hình gemini-3.7-flash không trả về nội dung văn bản');
      }

      return text;
    } catch (err) {
      lastErr = err;
      if (attempt < 2) {
        await new Promise(r => setTimeout(r, 1500));
      }
    }
  }

  throw lastErr;
}

/**
 * Gửi yêu cầu trò chuyện tới DUY NHẤT model gemini-3.7-flash
 * 
 * @param {Array<{role: string, content: string}>} messages - Lịch sử hội thoại
 * @param {string} customSystemInstruction - Tùy chọn ghi đè hoặc bổ sung system instruction
 * @returns {Promise<string>}
 */
async function generateChatResponse(messages, customSystemInstruction = '') {
  // Chuẩn hóa định dạng tin nhắn sang chuẩn Gemini: role user/model và parts
  const formattedContents = messages
    .filter(m => m && m.content && m.content.trim())
    .map(msg => ({
      role: msg.role === 'assistant' || msg.role === 'model' ? 'model' : 'user',
      parts: [{ text: msg.content }]
    }));

  if (formattedContents.length === 0) {
    throw new Error('Nội dung tin nhắn rỗng');
  }

  const systemPromptText = customSystemInstruction
    ? `${MOVIE_AI_SYSTEM_INSTRUCTION}\n\nThông tin bổ sung:\n${customSystemInstruction}`
    : MOVIE_AI_SYSTEM_INSTRUCTION;

  // 1. Thử gọi qua Vertex AI với gemini-3.7-flash nếu có credentials
  const creds = loadCredentials();
  if (creds) {
    try {
      const token = await getAccessToken();
      const projectId = creds.project_id;
      const location = DEFAULT_LOCATION;
      const endpoint = `https://${location}-aiplatform.googleapis.com/v1/projects/${projectId}/locations/${location}/publishers/google/models/${TARGET_MODEL}:generateContent`;

      const callVertex = async (useSearchTool = true) => {
        const payload = {
          systemInstruction: { parts: [{ text: systemPromptText }] },
          contents: formattedContents,
          generationConfig: {
            temperature: 0.7,
            maxOutputTokens: 4096,
            topP: 0.95
          }
        };

        if (useSearchTool) {
          payload.tools = [{ googleSearch: {} }];
        }

        return await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload)
        });
      };

      let response = await callVertex(true);
      if (!response.ok && response.status === 400) {
        response = await callVertex(false);
      }

      if (response.ok) {
        const data = await response.json();
        const parts = data.candidates?.[0]?.content?.parts || [];
        const text = parts
          .filter(p => p.text && !p.thought)
          .map(p => p.text)
          .join('');

        if (text) {
          console.log(`✅ [VertexAI] Phản hồi thành công từ model: ${TARGET_MODEL}`);
          return text;
        }
      } else {
        const errText = await response.text();
        console.warn(`⚠️ [VertexAI] Gọi ${TARGET_MODEL} thất bại (HTTP ${response.status}): ${errText.slice(0, 150)}`);
      }
    } catch (vertexErr) {
      console.warn(`⚠️ [VertexAI] Lỗi khi gọi Vertex AI với ${TARGET_MODEL}:`, vertexErr.message);
    }
  }

  // 2. Gọi qua Google Generative Language API với DUY NHẤT model gemini-3.7-flash
  if (process.env.GEMINI_API_KEY) {
    console.log(`🔄 [GeminiAPI] Đang xử lý qua Generative Language API với model: ${TARGET_MODEL}`);
    return await callGenerativeLanguageApi(formattedContents, systemPromptText, false);
  }

  throw new Error('Chưa cấu hình Google Cloud credentials hoặc GEMINI_API_KEY cho mô hình gemini-3.7-flash');
}

/**
 * Stream phản hồi từ DUY NHẤT model gemini-3.7-flash — trả về ReadableStream (SSE)
 */
async function streamChatResponse(messages, customSystemInstruction = '') {
  const formattedContents = messages
    .filter(m => m && m.content && m.content.trim())
    .map(msg => ({
      role: msg.role === 'assistant' || msg.role === 'model' ? 'model' : 'user',
      parts: [{ text: msg.content }]
    }));

  if (formattedContents.length === 0) throw new Error('Nội dung tin nhắn rỗng');

  const systemPromptText = customSystemInstruction
    ? `${MOVIE_AI_SYSTEM_INSTRUCTION}\n\nThông tin bổ sung:\n${customSystemInstruction}`
    : MOVIE_AI_SYSTEM_INSTRUCTION;

  // 1. Thử stream qua Vertex AI với gemini-3.7-flash
  const creds = loadCredentials();
  if (creds) {
    try {
      const token = await getAccessToken();
      const projectId = creds.project_id;
      const location = DEFAULT_LOCATION;
      const endpoint = `https://${location}-aiplatform.googleapis.com/v1/projects/${projectId}/locations/${location}/publishers/google/models/${TARGET_MODEL}:streamGenerateContent?alt=sse`;

      const payload = {
        systemInstruction: { parts: [{ text: systemPromptText }] },
        contents: formattedContents,
        generationConfig: {
          temperature: 0.7,
          maxOutputTokens: 4096,
          topP: 0.95
        },
        tools: [{ googleSearch: {} }]
      };

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (response.ok && response.body) {
        console.log(`🔄 [VertexAI] Bắt đầu stream từ model: ${TARGET_MODEL}`);
        return response.body;
      } else {
        const errText = await response.text();
        console.warn(`⚠️ [VertexAI] Stream ${TARGET_MODEL} thất bại (HTTP ${response.status}): ${errText.slice(0, 150)}`);
      }
    } catch (vertexErr) {
      console.warn(`⚠️ [VertexAI] Lỗi stream Vertex AI với ${TARGET_MODEL}:`, vertexErr.message);
    }
  }

  // 2. Stream qua Google Generative Language API với DUY NHẤT model gemini-3.7-flash
  if (process.env.GEMINI_API_KEY) {
    console.log(`🔄 [GeminiAPI] Bắt đầu stream từ Generative Language API với model: ${TARGET_MODEL}`);
    return await callGenerativeLanguageApi(formattedContents, systemPromptText, true);
  }

  throw new Error('Chưa cấu hình Google Cloud credentials hoặc GEMINI_API_KEY cho mô hình gemini-3.7-flash');
}

module.exports = {
  TARGET_MODEL,
  VERTEX_MODELS,
  isConfigured,
  generateChatResponse,
  streamChatResponse,
  MOVIE_AI_SYSTEM_INSTRUCTION
};
