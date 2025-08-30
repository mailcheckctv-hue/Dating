
/**
 * LoveConnect - Enhanced server.js (avatar, friends, conversations, image-first feed)
 * Keeps all existing routes; adds safe, backward-compatible endpoints:
 *  - POST   /api/profile/avatar     (upload & set avatarUrl)
 *  - POST   /api/friends/:id        (toggle follow/friend request-style add)
 *  - GET    /api/friends            (list mutual friends: users who list each other)
 *  - GET    /api/conversations      (recent chat heads with last message)
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
app.use(express.json({ limit: '10mb' }));
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
const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const ok = /\.(png|jpe?g|gif|webp|mp4|webm|ogg|mov|heic)$/i.test(file.originalname || '');
    if (ok) return cb(null, true);
    cb(new Error('Định dạng không hỗ trợ'));
  }
});

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
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], // NEW: simple friends list
}, { timestamps: true });

const postSchema = new mongoose.Schema({
  reactions: { type: Object, default: {} },
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
app.use('/uploads', (req, res, next) => {
  // 7 ngày cache ảnh/video
  res.set('Cache-Control', 'public, max-age=604800, immutable');
  next();
}, express.static(uploadDir));
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

// NEW: upload avatar
app.post('/api/profile/avatar', auth, upload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'Chưa có ảnh' });
  const fileUrl = `/uploads/${req.file.filename}`;
  const user = await User.findByIdAndUpdate(req.user.id, { avatarUrl: fileUrl }, { new: true }).lean();
  res.json({ avatarUrl: fileUrl, user });
});

// ---------- Upload (generic file/image) ----------
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

// ---------- Friends ----------
// Toggle add/remove friend (simple): if id exists in my list -> remove, else add.
app.post('/api/friends/:id', auth, async (req, res) => {
  const otherId = req.params.id;
  if (otherId === req.user.id) return res.status(400).json({ message: 'Không thể tự kết bạn' });
  const me = await User.findById(req.user.id);
  const idx = me.friends.findIndex(f => f.toString() === otherId);
  if (idx >= 0) me.friends.splice(idx, 1);
  else me.friends.push(otherId);
  await me.save();
  res.json({ success: true, friends: me.friends });
});

// List mutual friends: both users include each other in friends[]
app.get('/api/friends', auth, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me) return res.status(404).json({ message: 'Not found' });
  const candidates = await User.find({ _id: { $in: me.friends } }).select('username avatarUrl').lean();
  const mutual = [];
  for (const u of candidates) {
    const uu = await User.findById(u._id).select('friends username avatarUrl').lean();
    const list = (uu.friends || []).map(x => x.toString());
    if (list.includes(req.user.id)) mutual.push({ _id: u._id, username: u.username, avatarUrl: u.avatarUrl });
  }
  res.json(mutual);
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

// NEW: conversation heads (last message per peer)
app.get('/api/conversations', auth, async (req, res) => {
  try {
    const pipeline = [
      { $match: { $or: [ { sender: new mongoose.Types.ObjectId(req.user.id) }, { receiver: new mongoose.Types.ObjectId(req.user.id) } ] } },
      { $sort: { createdAt: -1 } },
      { $group: {
          _id: {
            other: {
              $cond: [
                { $eq: ['$sender', new mongoose.Types.ObjectId(req.user.id)] },
                '$receiver', '$sender'
              ]
            }
          },
          lastMessage: { $first: '$$ROOT' }
        }
      },
      { $lookup: {
          from: 'users',
          localField: '_id.other',
          foreignField: '_id',
          as: 'otherUser'
        }
      },
      { $unwind: '$otherUser' },
      { $project: {
          otherId: '$_id.other',
          otherName: '$otherUser.username',
          otherAvatar: '$otherUser.avatarUrl',
          lastMessage: 1
        }
      },
      { $limit: 50 }
    ];
    const conv = await Message.aggregate(pipeline);
    res.json(conv);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Không lấy được danh sách hội thoại' });
  }
});


// ---------- Comments, Reactions, Delete Post, Unread Messages (NEW) ----------
const commentSchema = new mongoose.Schema({
  post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, default: '' },
  stickerUrl: { type: String, default: '' }
}, { timestamps: true });
const Comment = mongoose.model('Comment', commentSchema);

app.get('/api/posts/:id/comments', auth, async (req, res) => {
  const list = await Comment.find({ post: req.params.id })
    .sort({ createdAt: 1 })
    .populate('author', 'username avatarUrl')
    .lean();
  res.json(list);
});

app.post('/api/posts/:id/comments', auth, async (req, res) => {
  const body = req.body || {};
  if ((!body.content || !body.content.trim()) && !body.stickerUrl) {
    return res.status(400).json({ message: 'Nội dung trống' });
  }
  const c = await Comment.create({
    post: req.params.id,
    author: req.user.id,
    content: (body.content||'').trim(),
    stickerUrl: body.stickerUrl || ''
  });
  const populated = await c.populate('author', 'username avatarUrl');
  res.json(populated);
});

// Toggle reaction with any emoji key: like, heart, haha, wow, sad, angry...
app.post('/api/posts/:id/react/:emoji', auth, async (req, res) => {
  const { id, emoji } = req.params;
  const post = await Post.findById(id);
  if (!post) return res.status(404).json({ message: 'Không tìm thấy bài viết' });
  if (!post.reactions) post.reactions = {};
  const set = new Set((post.reactions[emoji] || []).map(u => u.toString()));
  if (set.has(req.user.id)) set.delete(req.user.id); else set.add(req.user.id);
  post.reactions[emoji] = Array.from(set);
  await post.save();
  res.json({ reactions: post.reactions });
});

// Delete own post (+ cascade delete comments)
app.delete('/api/posts/:id', auth, async (req, res) => {
  const p = await Post.findById(req.params.id);
  if (!p) return res.status(404).json({ message: 'Không tìm thấy' });
  if (p.author.toString() !== req.user.id) return res.status(403).json({ message: 'Không có quyền' });
  await Comment.deleteMany({ post: p._id });
  await p.deleteOne();
  res.json({ success: true });
});

// Unread messages count
app.get('/api/messages/unread-count', auth, async (req, res) => {
  const count = await Message.countDocuments({ receiver: req.user.id, read: false });
  res.json({ count });
});

// Mark conversation as read
app.patch('/api/messages/read/:otherId', auth, async (req, res) => {
  await Message.updateMany(
    { sender: req.params.otherId, receiver: req.user.id, read: false },
    { $set: { read: true } }
  );
  res.json({ success: true });
});


// ---------- VIP Stub ----------
app.post('/api/upgrade-vip', auth, async (req, res) => {
  const { plan } = req.body;
  await User.findByIdAndUpdate(req.user.id, { vip: plan || 'vip-week' });
  res.json({ success: true });
});

// ---------- Default routes ----------
app.get('/', (req, res) => {
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
        const rc = clients.get(data.receiverId);
        if (rc && rc.readyState === WebSocket.OPEN) rc.send(JSON.stringify(sendObj));
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


// --- WS Robust Broadcast ---
try {
  const wsClients = new Map(); // userId -> Set of sockets
  if (wss && wss.on) {
    wss.on('connection', (socket, req) => {
      try {
        const url = require('url');
        const q = url.parse(req.url, true).query || {};
        const token = q.token || (req.headers['sec-websocket-protocol']||'').split(',').pop()?.trim();
        let user = null;
        if (token) {
          try { user = jwt.verify(token, JWT_SECRET); } catch(e){}
        }
        if (!user) { socket.close(); return; }
        socket._uid = user.id;
        if (!wsClients.has(user.id)) wsClients.set(user.id, new Set());
        wsClients.get(user.id).add(socket);

        socket.on('close', () => {
          const set = wsClients.get(user.id);
          if (set) {
            set.delete(socket);
            if (set.size === 0) wsClients.delete(user.id);
          }
        });

        socket.on('message', async (raw) => {
          try {
            const data = JSON.parse(raw.toString());
            if (data.type === 'message' && data.text && data.receiverId) {
              // Save before broadcast
              const saved = await Message.create({ sender: user.id, receiver: data.receiverId, text: data.text, read: false });
              const populated = await saved.populate('sender', 'username avatarUrl');
              const msgObj = { type: 'message', ...populated.toObject() };

              // Deliver to receiver sockets
              const recvSet = wsClients.get(data.receiverId) || new Set();
              recvSet.forEach(s => { if (s.readyState === 1) s.send(JSON.stringify(msgObj)); });

              // Echo to sender sockets
              const sndSet = wsClients.get(user.id) || new Set();
              sndSet.forEach(s => { if (s.readyState === 1) s.send(JSON.stringify(msgObj)); });
            }
          } catch (e) { console.error('WS message error', e); }
        });
      } catch (e) { console.error('WS connection error', e); try { socket.close(); } catch(_){ } }
    });
  }
} catch (e) { console.error('WS attach failed', e); }

