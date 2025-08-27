require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const WebSocket = require('ws');
const http = require('http');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 10000;
const HOST = '0.0.0.0';

// ==================== MONGODB CONNECTION ====================
const MONGODB_URI = process.env.MONGODB_URI;

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ Đã kết nối MongoDB'))
.catch(err => console.error('❌ MongoDB error:', err.message));

// ==================== MIDDLEWARE ====================
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public'), {
  index: 'login.html'
}));

// ==================== SCHEMAS ====================
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  email: { type: String, unique: true },
  password: String,
  profile: {
    fullname: String,
    age: Number,
    gender: String,
    bio: String,
    location: String,
    avatar: String
  },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  matches: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  isVip: { type: Boolean, default: false },
  vipExpiration: Date,
  createdAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Message = mongoose.model('Message', MessageSchema);

// ==================== AUTH ====================
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token không tồn tại' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token không hợp lệ' });
    req.user = user;
    next();
  });
};

// ==================== WEBSOCKET ====================
const activeUsers = new Map();

wss.on('connection', ws => {
  ws.on('message', async data => {
    try {
      const msg = JSON.parse(data);

      if (msg.type === 'auth') {
        ws.userId = msg.userId;
        activeUsers.set(ws.userId, ws);
      }

      if (msg.type === 'message') {
        const newMsg = new Message({
          sender: msg.senderId,
          receiver: msg.receiverId,
          content: msg.content
        });
        await newMsg.save();

        const receiverWs = activeUsers.get(msg.receiverId);
        if (receiverWs) {
          receiverWs.send(JSON.stringify({
            type: 'message',
            message: {
              id: newMsg._id,
              sender: msg.senderId,
              content: msg.content,
              createdAt: newMsg.createdAt
            }
          }));
        }
      }
    } catch (e) {
      console.error('WS error:', e);
    }
  });

  ws.on('close', () => {
    if (ws.userId) activeUsers.delete(ws.userId);
  });
});

// ==================== API ROUTES ====================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', time: new Date().toISOString() });
});

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: 'Thiếu thông tin' });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashed });
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.status(201).json({ token, user });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ $or: [{ username }, { email: username }] });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ message: 'Sai thông tin đăng nhập' });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// Get profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.userId);
  res.json(user);
});

// Get messages
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
  const messages = await Message.find({
    $or: [
      { sender: req.user.userId, receiver: req.params.userId },
      { sender: req.params.userId, receiver: req.user.userId }
    ]
  }).sort({ createdAt: 1 });
  res.json(messages);
});

// ==================== ROUTES STATIC ====================
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ==================== START SERVER ====================
server.listen(PORT, HOST, () => {
  console.log(`🚀 Server chạy tại http://${HOST}:${PORT}`);
});
