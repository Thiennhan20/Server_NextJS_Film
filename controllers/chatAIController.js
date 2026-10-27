const axios = require('axios');
const vertexAiService = require('../services/vertexAiService');

// Fallback danh sách model nếu dùng GEMINI_API_KEY trực tiếp
const GEMINI_MODELS = [
    'gemini-2.5-flash',
    'gemini-2.5-pro',
    'gemini-2.0-flash',
    'gemini-1.5-flash'
];

const generateResponse = async (req, res) => {
    try {
        let { messages, system, message, prompt } = req.body;

        // Chuẩn hóa input nếu client gửi string đơn lẻ
        if (!messages && (message || prompt)) {
            messages = [{ role: 'user', content: message || prompt }];
        }

        if (!messages || !Array.isArray(messages) || messages.length === 0) {
            return res.status(400).json({ error: 'Nội dung tin nhắn không hợp lệ (messages array required).' });
        }

        let replyText = null;

        // 1. ƯU TIÊN 1: Sử dụng Google Cloud Vertex AI (Service Account Key đã nạp trên Render hoặc local)
        if (vertexAiService.isConfigured()) {
            try {
                replyText = await vertexAiService.generateChatResponse(messages, system);
            } catch (err) {
                console.warn('⚠️ [ChatAI] Vertex AI gặp sự cố:', err.message);
            }
        }

        // 2. ƯU TIÊN 2: Fallback qua GEMINI_API_KEY (nếu có cấu hình)
        if (!replyText && process.env.GEMINI_API_KEY) {
            const formattedContents = messages.map(msg => ({
                role: msg.role === 'assistant' || msg.role === 'model' ? 'model' : 'user',
                parts: [{ text: msg.content }]
            }));

            for (const modelName of GEMINI_MODELS) {
                try {
                    const response = await axios.post(
                        `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${process.env.GEMINI_API_KEY}`,
                        {
                            systemInstruction: { parts: [{ text: system || vertexAiService.MOVIE_AI_SYSTEM_INSTRUCTION }] },
                            contents: formattedContents,
                        },
                        {
                            headers: { 'Content-Type': 'application/json' },
                            timeout: 15000
                        }
                    );

                    const text = response.data.candidates?.[0]?.content?.parts?.[0]?.text;
                    if (text) {
                        replyText = text;
                        console.log(`✅ [ChatAI] Fallback thành công qua GEMINI_API_KEY với model: ${modelName}`);
                        break;
                    }
                } catch (err) {
                    console.warn(`⚠️ [ChatAI] Bỏ qua ${modelName}: HTTP ${err.response?.status || err.message}`);
                }
            }
        }

        // 3. Trả về phản hồi nếu lấy được kết quả
        if (replyText) {
            return res.json({
                reply: replyText,
                choices: [
                    {
                        message: {
                            role: 'assistant',
                            content: replyText
                        }
                    }
                ]
            });
        }

        // Nếu không có nguồn nào trả lời được
        if (!vertexAiService.isConfigured() && !process.env.GEMINI_API_KEY) {
            return res.status(500).json({
                error: 'Hệ thống AI chưa được nạp Google Cloud credentials hoặc GEMINI_API_KEY trên Server.'
            });
        }

        return res.status(503).json({
            error: 'Nguồn AI đang quá tải hoặc tạm thời bảo trì. Bạn vui lòng thử lại sau giây lát!'
        });

    } catch (error) {
        console.error('❌ [ChatAI] Lỗi Server Nội Bộ:', error.message);
        res.status(500).json({ error: 'Hệ thống AI đang bảo trì. Vui lòng thử lại sau.' });
    }
};


/**
 * Streaming endpoint — SSE (Server-Sent Events)
 * Trả về từng chunk text realtime để frontend hiển thị giống ChatGPT
 */
const generateStreamResponse = async (req, res) => {
    try {
        let { messages, system, message, prompt } = req.body;

        if (!messages && (message || prompt)) {
            messages = [{ role: 'user', content: message || prompt }];
        }

        if (!messages || !Array.isArray(messages) || messages.length === 0) {
            return res.status(400).json({ error: 'Nội dung tin nhắn không hợp lệ.' });
        }

        if (!vertexAiService.isConfigured()) {
            return res.status(500).json({ error: 'Chưa cấu hình Vertex AI credentials.' });
        }

        // Set SSE headers
        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
            'Access-Control-Allow-Origin': '*'
        });

        const vertexStream = await vertexAiService.streamChatResponse(messages, system);

        // Đọc SSE stream từ Vertex AI, parse JSON, lọc thinking, gửi text chunks
        const reader = vertexStream.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, '\n');

            // Mỗi SSE event bắt đầu bằng "data: " và kết thúc bằng "\n\n"
            const events = buffer.split('\n\n');
            buffer = events.pop() || ''; // phần cuối có thể chưa hoàn chỉnh

            for (const event of events) {
                const dataLine = event.split('\n').find(line => line.startsWith('data: '));
                if (!dataLine) continue;

                const jsonStr = dataLine.slice(6).trim(); // Bỏ "data: "
                if (!jsonStr || jsonStr === '[DONE]') continue;

                try {
                    const parsed = JSON.parse(jsonStr);
                    const parts = parsed.candidates?.[0]?.content?.parts || [];

                    for (const part of parts) {
                        // Bỏ qua thinking parts của gemini-3.8-flash
                        if (part.thought) continue;
                        if (part.text) {
                            // Gửi chunk text tới frontend qua SSE
                            res.write(`data: ${JSON.stringify({ text: part.text })}\n\n`);
                        }
                    }
                } catch {
                    // Bỏ qua chunk JSON không hợp lệ
                }
            }
        }

        // Gửi signal kết thúc stream
        res.write(`data: [DONE]\n\n`);
        res.end();
        console.log('✅ [ChatAI] Stream hoàn tất.');

    } catch (error) {
        console.error('❌ [ChatAI] Stream error:', error.message);
        if (!res.headersSent) {
            res.status(500).json({ error: 'Lỗi stream AI.' });
        } else {
            res.write(`data: ${JSON.stringify({ error: error.message })}\n\n`);
            res.end();
        }
    }
};

module.exports = { generateResponse, generateStreamResponse };
