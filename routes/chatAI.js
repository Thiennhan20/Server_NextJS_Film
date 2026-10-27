const express = require('express');
const router = express.Router();
const chatAIController = require('../controllers/chatAIController');

router.post('/', chatAIController.generateResponse);
router.post('/chat', chatAIController.generateResponse);
router.post('/stream', chatAIController.generateStreamResponse);

module.exports = router;
