/**
 * LoveConnect - Full server.js
 * Features: Auth (JWT), Users, Posts (upload), Suggested users,
 * WebSocket chat, Static hosting for /public, healthcheck, VIP stub.
 */
require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const http = require('http');
const WebSocket = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ---------- ENV & Mongo ----------
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_please_change';
const MONGO = process.env.MONGODB_URI || process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/loveconnect';

mongoose
  .connect(MONGO, { dbName: 'loveconnect' })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('Mongo error:', err.message));

// ---------- Middlewares ----------
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// ensure /uploads exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// Multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname || '');
    cb(null, unique + ext);
  }
});
const upload = multer({ storage });

// ---------- Schemas ----------
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  gender: { type: String, enum: ['Nam', 'Nữ', 'Khác'], default: 'Khác' },
  avatarUrl: String,
  location: String,
  income: String,
  vip: { type: String, enum: ['none', 'vip-week', 'basic', 'premium'], default: 'none' },
}, { timestamps: true });

const postSchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: String,
  fileUrl: String,
  fileName: String,
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: String,
  fileUrl: String,
  fileName: String,
  read: { type: Boolean, default: false },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Message = mongoose.model('Message', messageSchema);

// ---------- Helpers ----------
function signToken(user) {
  return jwt.sign({ id: user._id, email: user.email, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
}
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.substring(7) : null;
  if (!token) return res.status(401).json({ message: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// ---------- Static ----------
const publicDir = path.join(__dirname, 'public');
app.use('/uploads', express.static(uploadDir));
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
}

// ---------- Healthcheck ----------
app.get('/healthz', (req, res) => res.json({ ok: true }));

// ---------- Auth Routes ----------
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, gender } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: 'Thiếu dữ liệu' });
    const existed = await User.findOne({ email });
    if (existed) return res.status(400).json({ message: 'Email đã tồn tại' });
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ username, email, password: hash, gender });
    const token = signToken(user);
    res.json({ token, user: { id: user._id, username: user.username, email: user.email } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Lỗi máy chủ' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Email hoặc mật khẩu không đúng' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: 'Email hoặc mật khẩu không đúng' });
    const token = signToken(user);
    res.json({ token, user: { id: user._id, username: user.username, email: user.email } });
  } catch (e) {
    res.status(500).json({ message: 'Lỗi máy chủ' });
  }
});

// ---------- Profile ----------
app.get('/api/profile', auth, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  res.json(me);
});

// ---------- Upload (file/image) ----------
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'Chưa có file' });
  const fileUrl = `/uploads/${req.file.filename}`;
  res.json({ fileUrl, fileName: req.file.originalname || req.file.filename });
});

// ---------- Posts ----------
app.get('/api/posts', auth, async (req, res) => {
  const posts = await Post.find().sort({ createdAt: -1 }).limit(50).populate('author', 'username avatarUrl').lean();
  res.json(posts);
});

app.post('/api/posts', auth, upload.single('file'), async (req, res) => {
  try {
    let fileUrl, fileName;
    if (req.file) {
      fileUrl = `/uploads/${req.file.filename}`;
      fileName = req.file.originalname || req.file.filename;
    } else if (req.body.fileUrl) {
      fileUrl = req.body.fileUrl;
      fileName = req.body.fileName;
    }
    const post = await Post.create({
      author: req.user.id,
      content: req.body.content || '',
      fileUrl, fileName
    });
    const populated = await post.populate('author', 'username avatarUrl');
    res.json(populated);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Không tạo được bài viết' });
  }
});

// ---------- Suggested users ----------
app.get('/api/users/suggested', auth, async (req, res) => {
  const users = await User.find({ _id: { $ne: req.user.id } }).select('username avatarUrl gender location').limit(12).lean();
  res.json(users);
});

// ---------- Messages (REST for history) ----------
app.get('/api/messages/:otherId', auth, async (req, res) => {
  const other = req.params.otherId;
  const msgs = await Message.find({
    $or: [
      { sender: req.user.id, receiver: other },
      { sender: other, receiver: req.user.id }
    ]
  }).sort({ createdAt: 1 }).lean();
  res.json(msgs);
});

// ---------- VIP Stub ----------
app.post('/api/upgrade-vip', auth, async (req, res) => {
  const { plan } = req.body;
  await User.findByIdAndUpdate(req.user.id, { vip: plan || 'vip-week' });
  res.json({ success: true });
});

// ---------- Default routes ----------
app.get('/', (req, res) => {
  // serve login if public exists; otherwise simple text
  const loginPath = path.join(publicDir, 'login.html');
  if (fs.existsSync(loginPath)) return res.sendFile(loginPath);
  res.send('LoveConnect API is running.');
});

// ---------- WebSocket ----------
const clients = new Map(); // userId -> ws

function wsAuth(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

wss.on('connection', (socket, req) => {
  // token from query ?token=...
  const params = new URLSearchParams((req.url || '').split('?')[1]);
  const token = params.get('token');
  const user = wsAuth(token);
  if (!user) {
    socket.close();
    return;
  }
  clients.set(user.id, socket);

  socket.on('message', async (msg) => {
    try {
      const data = JSON.parse(msg.toString());
      if (data.type === 'message') {
        const payload = {
          sender: user.id,
          receiver: data.receiverId,
          content: data.content || '',
          fileUrl: data.fileUrl,
          fileName: data.fileName
        };
        const saved = await Message.create(payload);
        const sendObj = {
          type: 'message',
          _id: saved._id,
          sender: { _id: user.id, username: user.username },
          receiver: data.receiverId,
          content: payload.content,
          fileUrl: payload.fileUrl,
          fileName: payload.fileName,
          createdAt: saved.createdAt
        };
        // send to receiver if online
        const rc = clients.get(data.receiverId);
        if (rc && rc.readyState === WebSocket.OPEN) rc.send(JSON.stringify(sendObj));
        // echo back to sender
        if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(sendObj));
      }
    } catch (e) {
      console.error('WS error', e.message);
    }
  });

  socket.on('close', () => {
    clients.delete(user.id);
  });
});

server.listen(PORT, () => {
  console.log('Server running on port', PORT);
});
