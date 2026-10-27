const axios = require('axios');
const vertexAiService = require('../services/vertexAiService');

// Model nhóm 1 (Vertex AI ổn định 100%): Ưu tiên gemini-2.5-flash, fallback sang gemini-2.5-pro và gemini-2.5-flash-lite
const CANDIDATE_MODELS = vertexAiService.CANDIDATE_MODELS || ['gemini-2.5-flash', 'gemini-2.5-pro', 'gemini-2.5-flash-lite'];

const generateResponse = async (req, res) => {
    try {
        let { messages, system, message, prompt, currentMovie } = req.body;

        // Chuẩn hóa input nếu client gửi string đơn lẻ
        if (!messages && (message || prompt)) {
            messages = [{ role: 'user', content: message || prompt }];
        }

        if (!messages || !Array.isArray(messages) || messages.length === 0) {
            return res.status(400).json({ error: 'Nội dung tin nhắn không hợp lệ (messages array required).' });
        }

        // Cắt tỉa ngữ cảnh: Giữ 8 tin nhắn gần nhất để phản hồi nhanh và tiết kiệm token
        if (messages.length > 8) {
            messages = messages.slice(-8);
        }

        // Bổ sung ngữ cảnh phim người dùng đang xem nếu có
        if (currentMovie && typeof currentMovie === 'string' && currentMovie.trim()) {
            const movieContext = `[Ngữ cảnh trang hiện tại: Người dùng đang ở trang phim "${currentMovie.trim()}". Nếu người dùng hỏi các câu hỏi ngắn hoặc dùng từ "phim này", "ai đóng", "review", hãy ưu tiên hiểu là đang nói về phim này.]`;
            system = system ? `${system}\n\n${movieContext}` : movieContext;
        }

        let replyText = null;

        // 1. Ưu tiên xử lý qua vertexAiService (các model nhóm 1)
        if (vertexAiService.isConfigured()) {
            try {
                replyText = await vertexAiService.generateChatResponse(messages, system);
            } catch (err) {
                console.warn('⚠️ [ChatAI] vertexAiService gặp sự cố:', err.message);
            }
        }

        // 2. Dự phòng trực tiếp qua GEMINI_API_KEY nếu vertexAiService chưa có kết quả
        if (!replyText && process.env.GEMINI_API_KEY) {
            const formattedContents = messages.map(msg => ({
                role: msg.role === 'assistant' || msg.role === 'model' ? 'model' : 'user',
                parts: [{ text: msg.content }]
            }));

            for (const modelName of CANDIDATE_MODELS) {
                try {
                    const response = await axios.post(
                        `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${process.env.GEMINI_API_KEY}`,
                        {
                            systemInstruction: { parts: [{ text: system || vertexAiService.MOVIE_AI_SYSTEM_INSTRUCTION }] },
                            contents: formattedContents,
                            generationConfig: {
                                temperature: 0.7,
                                maxOutputTokens: 4096,
                                topP: 0.95
                            }
                        },
                        {
                            headers: { 'Content-Type': 'application/json' },
                            timeout: 20000
                        }
                    );

                    const parts = response.data.candidates?.[0]?.content?.parts || [];
                    const text = parts
                        .filter(p => p.text && !p.thought)
                        .map(p => p.text)
                        .join('');

                    if (text) {
                        replyText = text;
                        console.log(`✅ [ChatAI] Phản hồi thành công từ model: ${modelName}`);
                        break;
                    }
                } catch (err) {
                    console.warn(`⚠️ [ChatAI] Gọi ${modelName} qua API Key thất bại: ${err.response?.status || err.message}`);
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
                error: 'Hệ thống AI chưa được cấu hình Google Cloud credentials hoặc GEMINI_API_KEY trên Server.'
            });
        }

        return res.status(503).json({
            error: 'Mô hình AI đang quá tải tạm thời. Bạn vui lòng thử lại sau giây lát!'
        });

    } catch (error) {
        console.error('❌ [ChatAI] Lỗi Server Nội Bộ:', error.message);
        res.status(500).json({ error: 'Hệ thống AI đang bảo trì. Vui lòng thử lại sau.' });
    }
};


/**
 * Streaming endpoint — SSE (Server-Sent Events)
 * Trả về từng chunk text realtime sử dụng các model nhóm 1 (gemini-2.5-flash, gemini-2.5-pro, gemini-2.5-flash-lite)
 */
const generateStreamResponse = async (req, res) => {
    try {
        let { messages, system, message, prompt, currentMovie } = req.body;

        if (!messages && (message || prompt)) {
            messages = [{ role: 'user', content: message || prompt }];
        }

        if (!messages || !Array.isArray(messages) || messages.length === 0) {
            return res.status(400).json({ error: 'Nội dung tin nhắn không hợp lệ.' });
        }

        // Cắt tỉa ngữ cảnh: Giữ 8 tin nhắn gần nhất
        if (messages.length > 8) {
            messages = messages.slice(-8);
        }

        // Bổ sung ngữ cảnh phim người dùng đang xem nếu có
        if (currentMovie && typeof currentMovie === 'string' && currentMovie.trim()) {
            const movieContext = `[Ngữ cảnh trang hiện tại: Người dùng đang ở trang phim "${currentMovie.trim()}". Nếu người dùng hỏi các câu hỏi ngắn hoặc dùng từ "phim này", "ai đóng", "review", hãy ưu tiên hiểu là đang nói về phim này.]`;
            system = system ? `${system}\n\n${movieContext}` : movieContext;
        }

        if (!vertexAiService.isConfigured() && !process.env.GEMINI_API_KEY) {
            return res.status(500).json({ error: 'Chưa cấu hình credentials cho mô hình AI.' });
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

        // Đọc SSE stream từ Vertex AI / Generative Language API, parse JSON, lọc thinking, gửi text chunks
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
                        // Bỏ qua thinking parts
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
        const activeModel = vertexAiService.PRIMARY_MODEL || 'gemini-2.5-flash';
        console.log(`✅ [ChatAI] Stream hoàn tất với model: ${activeModel}`);

    } catch (error) {
        console.error('❌ [ChatAI] Stream error:', error.message);
        if (!res.headersSent) {
            res.status(500).json({ error: 'Lỗi stream AI.' });
        } else if (!res.writableEnded) {
            res.write(`data: ${JSON.stringify({ error: error.message })}\n\n`);
            res.end();
        }
    }
};

module.exports = { generateResponse, generateStreamResponse };
