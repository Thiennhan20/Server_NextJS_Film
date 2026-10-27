const express = require('express');
const router = express.Router();
const chatAIController = require('../controllers/chatAIController');
const limitChatRequests = require('../middleware/chatRateLimiter');

router.post('/', limitChatRequests, chatAIController.generateResponse);
router.post('/chat', limitChatRequests, chatAIController.generateResponse);
router.post('/stream', limitChatRequests, chatAIController.generateStreamResponse);

module.exports = router;
