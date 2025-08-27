// ================== server.js ==================
// Dating App - Backend server with WebSocket, Upload, VIP, Posts, Messages
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { WebSocketServer } = require('ws');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ============ DB ==============
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// ============ SCHEMAS ==========
const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
  email: String,
  gender: String,
  avatar: String,
  role: { type: String, default: 'user' }, // user | admin
  isVip: { type: Boolean, default: false },
});
const User = mongoose.model('User', UserSchema);

const MessageSchema = new mongoose.Schema({
  sender: String,
  receiver: String,
  content: String,
  image: String,
  fileUrl: String,
  fileName: String,
  createdAt: { type: Date, default: Date.now },
});
const Message = mongoose.model('Message', MessageSchema);

const PostSchema = new mongoose.Schema({
  userId: String,
  content: String,
  image: String,
  video: String,
  createdAt: { type: Date, default: Date.now },
});
const Post = mongoose.model('Post', PostSchema);

const VipRequestSchema = new mongoose.Schema({
  userId: String,
  package: String,
  createdAt: { type: Date, default: Date.now },
  status: { type: String, default: 'pending' }, // pending | approved | rejected
});
const VipRequest = mongoose.model('VipRequest', VipRequestSchema);

const NotificationSchema = new mongoose.Schema({
  message: String,
  createdAt: { type: Date, default: Date.now },
});
const Notification = mongoose.model('Notification', NotificationSchema);

// ============ AUTH =============
function authMiddleware(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.userId = decoded.id;
    req.role = decoded.role;
    next();
  });
}

// ============ UPLOAD ===========
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  res.json({ fileUrl, fileName: req.file.originalname });
});

// ============ AUTH ROUTES ======
app.post('/api/register', async (req, res) => {
  const { username, password, email, gender } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = await User.create({ username, password: hashed, email, gender });

  // gợi ý bạn bè theo giới tính đối lập
  let suggest = '';
  if (gender === 'male') {
    suggest = `${username} ơi, Thư cùng nhiều bạn nữ khác đang chờ bạn để trò chuyện!`;
  } else {
    suggest = `${username} ơi, Nam cùng nhiều bạn nam khác đang chờ bạn để kết nối!`;
  }

  res.json({ user, suggest });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ error: 'User not found' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid password' });
  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
  res.json({ token, user });
});

// ============ PROFILE ==========
app.get('/api/profile', authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId);
  res.json(user);
});
app.put('/api/profile', authMiddleware, upload.single('avatar'), async (req, res) => {
  let avatarUrl;
  if (req.file) {
    avatarUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  }
  const user = await User.findByIdAndUpdate(req.userId, { ...req.body, ...(avatarUrl && { avatar: avatarUrl }) }, { new: true });
  res.json(user);
});

// ============ POSTS ============
app.post('/api/posts', authMiddleware, upload.single('media'), async (req, res) => {
  let image, video;
  if (req.file) {
    const url = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    if (req.file.mimetype.startsWith('image/')) image = url;
    else if (req.file.mimetype.startsWith('video/')) video = url;
  }
  const post = await Post.create({ userId: req.userId, content: req.body.content, image, video });
  res.json(post);
});
app.get('/api/posts', authMiddleware, async (req, res) => {
  const posts = await Post.find().sort({ createdAt: -1 }).limit(50);
  res.json(posts);
});

// ============ VIP ============
app.post('/api/upgrade-vip', authMiddleware, async (req, res) => {
  const { package } = req.body;
  const vip = await VipRequest.create({ userId: req.userId, package });
  res.json(vip);
});
app.post('/api/admin/vip/:id/:action', authMiddleware, async (req, res) => {
  if (req.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const vip = await VipRequest.findById(req.params.id);
  vip.status = req.params.action === 'approve' ? 'approved' : 'rejected';
  await vip.save();
  if (vip.status === 'approved') {
    await User.findByIdAndUpdate(vip.userId, { isVip: true });
  }
  res.json(vip);
});

// ============ FRIENDS =========
app.get('/api/users/suggested', authMiddleware, async (req, res) => {
  const users = await User.find({ _id: { $ne: req.userId } }).sort({ createdAt: -1 }).limit(10);
  res.json(users);
});

// ============ ADMIN ===========
app.get('/api/admin/notifications', authMiddleware, async (req, res) => {
  if (req.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const notis = await Notification.find().sort({ createdAt: -1 }).limit(50);
  res.json(notis);
});

// ============ WEBSOCKET =======
const server = app.listen(process.env.PORT || 10000, () =>
  console.log('Server running on port', process.env.PORT || 10000)
);
const wss = new WebSocketServer({ server });
let clients = new Map();

wss.on('connection', (ws, req) => {
  const params = new URLSearchParams(req.url.replace('/?', ''));
  const token = params.get('token');
  if (!token) return ws.close();
  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) return ws.close();
    ws.userId = decoded.id;
    clients.set(ws.userId, ws);

    ws.on('message', async (msg) => {
      try {
        const data = JSON.parse(msg);
        if (data.type === 'message') {
          const message = await Message.create({
            sender: ws.userId,
            receiver: data.receiverId,
            content: data.content || null,
            image: data.image || null,
            fileUrl: data.fileUrl || null,
            fileName: data.fileName || null,
          });
          const receiverWS = clients.get(data.receiverId);
          if (receiverWS) receiverWS.send(JSON.stringify({ type: 'message', message }));
          ws.send(JSON.stringify({ type: 'message', message }));
        }
        if (data.type === 'typing') {
          const receiverWS = clients.get(data.receiverId);
          if (receiverWS) receiverWS.send(JSON.stringify({ type: 'typing', from: ws.userId }));
        }
      } catch (e) {
        console.error('WS error:', e);
      }
    });

    ws.on('close', () => {
      clients.delete(ws.userId);
    });
  });
});

// ============ SEED ADMIN ======
(async () => {
  const exists = await User.findOne({ username: 'Admin_CFC' });
  if (!exists) {
    const hashed = await bcrypt.hash('687969', 10);
    await User.create({ username: 'Admin_CFC', password: hashed, role: 'admin' });
    console.log('Admin_CFC created');
  }
})();
