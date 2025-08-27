// server.js - simplified example (full version bạn sẽ mở rộng thêm)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { WebSocketServer } = require('ws');
const app = express();
app.use(cors());
app.get('/', (req, res) => res.send('Dating App Server Running'));

// WebSocket setup
const server = app.listen(process.env.PORT || 10000, () =>
  console.log('Server started')
);
const wss = new WebSocketServer({ server });
wss.on('connection', ws => {
  ws.on('message', msg => {
    console.log('Received:', msg.toString());
    ws.send('Echo: ' + msg.toString());
  });
});
