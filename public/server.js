const User = require('./models/User');

/**
 * server.js - Full LoveConnect (Giai đoạn 1-3)
 * - Includes: auth, roles, admin default, daily quota, groups, banned words,
 *   analytics (basic), notifications (mock), SMS packages (mock), 2FA (mock),
 *   backup export, posts/comments/friends/messages, file upload, avatar,
 *   single WebSocket handler (no duplicate), and admin APIs.
 *
 * ENV expected:
 * - MONGODB_URI or MONGO_URI: MongoDB connection string
 * - JWT_SECRET: secret for JWT
 * - ADMIN_RESET_SECRET: optional secret to allow resetting admin password via internal endpoint
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
const { stringify } = require('csv-stringify/sync');
const xlsx = require('xlsx');
const EventEmitter = require('events');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const eventBus = new EventEmitter();

// ENV
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_please_change';
const MONGO = process.env.MONGODB_URI || process.env.MONGO_URL || process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/loveconnect';
const ADMIN_RESET_SECRET = process.env.ADMIN_RESET_SECRET || '';

// Connect Mongo
mongoose.connect(MONGO, { dbName: 'loveconnect' })
  .then(async () => {
    console.log('MongoDB connected');
    try { await ensureDefaultAdmin(); } catch(e){ console.error('ensureDefaultAdmin error', e); }
  })
  .catch((err) => console.error('Mongo error:', err.message));

// Middlewares
app.use(cors());
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));

// Upload dir
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random()*1e9);
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
  plainPassword: String,
  gender: { type: String, enum: ['Nam','Nữ','Khác'], default: 'Khác' },
  avatarUrl: String,
  location: String,
  vip: { type: String, enum: ['none','vip-week','basic','premium'], default: 'none' },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  income: String,
  job: String,
  phone: String,

  // admin / quota
  role: { type: String, enum: ['guest','user','moderator','admin','superadmin'], default: 'user' },
  dailyLimit: { type: Number, default: 5 },
  dailySent: { type: Number, default: 0 },
  weeklyLimit: { type: Number, default: 0 },
  monthlyLimit: { type: Number, default: 0 },
  yearlyLimit: { type: Number, default: 0 },
  dailyResetAt: { type: Date, default: () => { const d = new Date(); d.setHours(24,0,0,0); return d; } },
  isLocked: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  smsBlocked: { type: Boolean, default: false },
  passwordChangeCount: { type: Number, default: 0 },

  smsPackages: [{ qty: Number, createdAt: Date }]
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
  text: String,
  fileUrl: String,
  fileName: String,
  read: { type: Boolean, default: false },
}, { timestamps: true });

const groupSchema = new mongoose.Schema({
  name: String,
  slug: String,
  description: String,
  isPrivate: { type: Boolean, default: false },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  moderators: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  messageLimitPerDay: { type: Number, default: 1000 }
}, { timestamps: true });

const bannedSchema = new mongoose.Schema({ word: String }, { timestamps: true });
const notificationSchema = new mongoose.Schema({
  title: String,
  message: String,
  target: String, // all / user / segment
  meta: Object
}, { timestamps: true });

const twoFASchema = new mongoose.Schema({ user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, secret: String, enabled: Boolean }, { timestamps: true });

const commentSchema = new mongoose.Schema({ 
  post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' }, 
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
  content: String, 
  stickerUrl: String 
}, { timestamps: true });

const adminLogSchema = new mongoose.Schema({
  adminId: { type: String, required: true },
  action: String,
  targetUserId: String,
  payload: Object,
  createdAt: { type: Date, default: Date.now }
});

const Post = mongoose.model('Post', postSchema);
const Message = mongoose.model('Message', messageSchema);
const Group = mongoose.model('Group', groupSchema);
const Banned = mongoose.model('Banned', bannedSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const TwoFA = mongoose.model('TwoFA', twoFASchema);
const Comment = mongoose.model('Comment', commentSchema);
const AdminLog = mongoose.model('AdminLog', adminLogSchema);

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

function requireRole(...roles) {
  return async (req,res,next) => {
    const u = await User.findById(req.user.id).select('role');
    if (!u) return res.status(401).json({ message: 'Unauthorized' });
    if (!roles.includes(u.role)) return res.status(403).json({ message: 'Forbidden' });
    req.me = u;
    next();
  };
}

function nextMidnight() {
  const d = new Date(); d.setHours(24,0,0,0); return d;
}

function publicUser(user) {
  return {
    id: user._id,
    username: user.username,
    email: user.email,
    avatarUrl: user.avatarUrl,
    role: user.role,
    gender: user.gender,
    location: user.location,
    vip: user.vip
  };
}

async function ensureDefaultAdmin() {
  try {
    const USERNAME = 'Admin_Check_1';
    const PLAIN = '87787323';
    const EMAIL = 'admin_check_1@local';
    let existing = await User.findOne({ $or: [{ username: USERNAME }, { email: EMAIL }] });
    if (!existing) {
      const hash = await bcrypt.hash(PLAIN, 10);
      const admin = new User({ username: USERNAME, email: EMAIL, password: hash, role: 'admin', dailyLimit: 999999, plainPassword: PLAIN });
      await admin.save();
      console.log('Default admin created:', admin._id.toString());
      existing = admin;
    }
    if (existing.username === USERNAME && existing.role !== 'admin') {
      existing.role = 'admin'; await existing.save();
    }
  } catch (e) {
    console.error('ensureDefaultAdmin failed', e);
  }
}

async function resetIfNeeded(userId) {
  const now = new Date();
  const next = nextMidnight();
  await User.updateOne({ _id: userId, dailyResetAt: { $lte: now } }, { $set: { dailySent: 0, dailyResetAt: next } });
}

async function tryConsumeDaily(userId) {
  await resetIfNeeded(userId);
  const user = await User.findById(userId).lean();
  if (!user) return false;
  if (['admin','superadmin'].includes(user.role)) return true;
  const updated = await User.findOneAndUpdate({ _id: userId, dailySent: { $lt: user.dailyLimit } }, { $inc: { dailySent: 1 } }, { new: true });
  return !!updated;
}

async function checkDailyLimit(userId, ws) {
  const ok = await tryConsumeDaily(userId);
  if (!ok && ws && ws.readyState && ws.readyState === WebSocket.OPEN) {
    try { ws.send(JSON.stringify({ type: 'error', code: 'quota_exceeded', message: 'Bạn đã vượt hạn mức tin nhắn hôm nay.' })); } catch {}
  }
  return ok;
}

async function getDailyStatus(userId) {
  await resetIfNeeded(userId);
  const u = await User.findById(userId).select('dailySent dailyLimit dailyResetAt').lean();
  if (!u) return null;
  return { dailySent: u.dailySent||0, dailyLimit: u.dailyLimit||0, dailyResetAt: u.dailyResetAt, remaining: Math.max(0, (u.dailyLimit||0)-(u.dailySent||0)) };
}

async function containsBanned(text) {
  if (!text) return false;
  const banned = await Banned.find().lean();
  for (const b of banned) {
    if (text.toLowerCase().includes((b.word||'').toLowerCase())) return true;
  }
  return false;
}

async function pushEvent(payload){
  try{
    await Notification.create({ type: payload.type, message: payload.message, meta: payload.meta||{} });
  }catch(e){ console.error("Notif save error", e); }
  eventBus.emit('event', payload);
}

// ---------- Static ----------
const publicDir = path.join(__dirname, 'public');
app.use('/uploads', express.static(uploadDir));
if (fs.existsSync(publicDir)) app.use(express.static(publicDir));

app.get('/healthz', (req,res)=> res.json({ ok: true }));

// ---------- Auth Routes ----------
app.post('/api/register', async (req,res)=>{
  try {
    const { username, email, password, gender } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: 'Thiếu dữ liệu' });
    const existed = await User.findOne({ email });
    if (existed) return res.status(400).json({ message: 'Email đã tồn tại' });
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ username, email, password: hash, plainPassword: password, gender });
    const token = signToken(user);
    res.json({ token, user: publicUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ message: 'Lỗi máy chủ' }); }
});

app.post('/api/login', async (req,res)=>{
  try {
    const { id, email, username, identifier, password } = req.body;
    let user = null;
    if (id) user = await User.findById(id);
    else if (email) user = await User.findOne({ email });
    else if (username) user = await User.findOne({ username });
    else if (identifier) {
      const ident = String(identifier).trim();
      if (/^[0-9a-fA-F]{24}$/.test(ident)) user = await User.findById(ident);
      if (!user) user = await User.findOne({ email: ident }) || await User.findOne({ username: ident });
    }
    if (!user) return res.status(404).json({ message: 'Không tìm thấy user' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: 'Sai mật khẩu' });

    const token = signToken(user);
    res.json({ token, user: publicUser(user) });
  } catch(e){ console.error(e); res.status(500).json({ message:'Lỗi máy chủ' }); }
});

app.post('/internal/reset-admin-password', async (req,res)=>{
  try {
    const { secret, username='Admin_Check_1', newPassword } = req.body;
    if (!ADMIN_RESET_SECRET) return res.status(403).json({ message: 'Reset not enabled' });
    if (!secret || secret !== ADMIN_RESET_SECRET) return res.status(403).json({ message: 'Invalid secret' });
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ message: 'newPassword required (>=6 chars)' });
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ message: 'Admin user not found' });
    user.password = await bcrypt.hash(newPassword, 10);
    user.plainPassword = newPassword;
    await user.save();
    pushEvent({ type:'new-user', message:`${user.email||user.username} vừa đăng ký`, meta:{ userId: user._id } });
    return res.json({ success: true, message: 'Password reset' });
  } catch(e){ console.error(e); res.status(500).json({ message: 'Error' }); }
});

// ---------- Profile & Avatar ----------
app.get('/api/profile', auth, async (req,res)=>{
  const me = await User.findById(req.user.id).lean();
  res.json(me);
});

app.get('/api/profile/limits', auth, async (req,res)=>{
  try {
    const status = await getDailyStatus(req.user.id);
    if (!status) return res.status(404).json({ message: 'Không tìm thấy người dùng' });
    res.json(status);
  } catch(e){ console.error(e); res.status(500).json({ message: 'Lỗi máy chủ' }); }
});

app.post('/api/profile/avatar', auth, upload.single('avatar'), async (req,res)=>{
  if (!req.file) return res.status(400).json({ message: 'Chưa có ảnh' });
  const fileUrl = `/uploads/${req.file.filename}`;
  await User.findByIdAndUpdate(req.user.id, { avatarUrl: fileUrl });
  res.json({ avatarUrl: fileUrl });
});

app.post('/api/upload', auth, upload.single('file'), async (req,res)=>{
  if (!req.file) return res.status(400).json({ message: 'Chưa có file' });
  const fileUrl = `/uploads/${req.file.filename}`;
  res.json({ fileUrl, fileName: req.file.originalname || req.file.filename });
});

// ---------- Posts ----------
app.get('/api/posts', auth, async (req,res)=>{
  const posts = await Post.find().sort({ createdAt:-1 }).limit(50).populate('author','username avatarUrl').lean();
  res.json(posts);
});

app.post('/api/posts', auth, upload.single('file'), async (req,res)=>{
  try {
    let fileUrl,fileName;
    if (req.file) { fileUrl = `/uploads/${req.file.filename}`; fileName = req.file.originalname || req.file.filename; }
    else if (req.body.fileUrl) { fileUrl = req.body.fileUrl; fileName = req.body.fileName; }
    const post = await Post.create({ author: req.user.id, content: req.body.content||'', fileUrl, fileName });
    const populated = await post.populate('author','username avatarUrl');
    res.json(populated);
  } catch(e){ console.error(e); res.status(500).json({ message: 'Không tạo được bài viết' }); }
});

// ---------- Friends ----------
app.post('/api/friends/:id', auth, async (req,res)=>{
  const otherId = req.params.id;
  if (otherId === req.user.id) return res.status(400).json({ message: 'Không thể tự kết bạn' });
  const me = await User.findById(req.user.id);
  const idx = me.friends.findIndex(f => f.toString() === otherId);
  if (idx >= 0) me.friends.splice(idx,1); else me.friends.push(otherId);
  await me.save();
  res.json({ success:true, friends: me.friends });
});

app.get('/api/friends', auth, async (req,res)=>{
  const me = await User.findById(req.user.id).lean();
  if (!me) return res.status(404).json({ message: 'Not found' });
  const candidates = await User.find({ _id: { $in: me.friends } }).select('username avatarUrl').lean();
  const mutual = [];
  for (const u of candidates) {
    const uu = await User.findById(u._id).select('friends username avatarUrl').lean();
    const list = (uu.friends||[]).map(x=>x.toString());
    if (list.includes(req.user.id)) mutual.push({ _id: u._id, username: u.username, avatarUrl: u.avatarUrl });
  }
  res.json(mutual);
});

// ---------- Messages REST ----------
app.get('/api/messages/count/:otherId', auth, async (req,res)=>{
  const other = req.params.otherId;
  const count = await Message.countDocuments({ $or: [{ sender: req.user.id, receiver: other }, { sender: other, receiver: req.user.id }] });
  res.json({ count });
});

app.get('/api/messages/sent-count/:otherId', auth, async (req,res)=>{
  const other = req.params.otherId;
  try { const count = await Message.countDocuments({ sender: req.user.id, receiver: other }); res.json({ count }); }
  catch(e){ res.status(500).json({ message: 'Không lấy được số tin nhắn đã gửi' }); }
});

app.get('/api/messages/:otherId', auth, async (req,res)=>{
  const other = req.params.otherId;
  const msgs = await Message.find({ $or: [{ sender: req.user.id, receiver: other }, { sender: other, receiver: req.user.id }] }).sort({ createdAt:1 }).lean();
  res.json(msgs);
});

app.get('/api/messages/unread-count', auth, async (req,res)=>{
  const count = await Message.countDocuments({ receiver: req.user.id, read: false });
  res.json({ count });
});

app.patch('/api/messages/read/:otherId', auth, async (req,res)=>{
  await Message.updateMany({ sender: req.params.otherId, receiver: req.user.id, read: false }, { $set: { read: true } });
  res.json({ success:true });
});

// ---------- Conversations ----------
app.get('/api/conversations', auth, async (req,res)=>{
  try {
    const pipeline = [
      { $match: { $or: [ { sender: new mongoose.Types.ObjectId(req.user.id) }, { receiver: new mongoose.Types.ObjectId(req.user.id) } ] } },
      { $sort: { createdAt: -1 } },
      { $group: { _id: { other: { $cond: [ { $eq: ['$sender', new mongoose.Types.ObjectId(req.user.id)] }, '$receiver', '$sender' ] } }, lastMessage: { $first: '$$ROOT' } } },
      { $lookup: { from: 'users', localField: '_id.other', foreignField: '_id', as: 'otherUser' } },
      { $unwind: '$otherUser' },
      { $project: { otherId: '$_id.other', otherName: '$otherUser.username', otherAvatar: '$otherUser.avatarUrl', lastMessage:1 } },
      { $limit: 50 }
    ];
    const conv = await Message.aggregate(pipeline);
    res.json(conv);
  } catch(e){ console.error(e); res.status(500).json({ message: 'Không lấy được danh sách hội thoại' }); }
});

app.get('/api/conversations-with-unread', auth, async (req,res)=>{
  try {
    const meId = new mongoose.Types.ObjectId(req.user.id);
    const pipeline = [
      { $match: { $or: [ { sender: meId }, { receiver: meId } ] } },
      { $sort: { createdAt: -1 } },
      { $group: {
          _id: { other: { $cond: [{ $eq: ['$sender', meId] }, '$receiver', '$sender'] } },
          lastMessage: { $first: '$$ROOT' },
          unreadCount: { $sum: { $cond: [ { $and: [ { $eq: ['$receiver', meId] }, { $eq: ['$read', false] } ] }, 1, 0 ] } }
        }
      },
      { $lookup: { from: 'users', localField: '_id.other', foreignField: '_id', as: 'otherUser' } },
      { $unwind: '$otherUser' },
      { $project: { otherId: '$_id.other', otherName: '$otherUser.username', otherAvatar: '$otherUser.avatarUrl', lastMessage:1, unreadCount:1 } },
      { $limit: 50 }
    ];
    const conv = await Message.aggregate(pipeline);
    res.json(conv);
  } catch(e){ console.error(e); res.status(500).json({ message: 'Không lấy được danh sách hội thoại (unread)' }); }
});

// ---------- Comments, Reactions, Delete Post ----------
app.get('/api/posts/:id/comments', auth, async (req,res)=>{
  const list = await Comment.find({ post: req.params.id }).sort({ createdAt:1 }).populate('author','username avatarUrl').lean();
  res.json(list);
});

app.post('/api/posts/:id/comments', auth, async (req,res)=>{
  const body = req.body || {};
  if ((!body.content || !body.content.trim()) && !body.stickerUrl) return res.status(400).json({ message: 'Nội dung trống' });
  const c = await Comment.create({ post: req.params.id, author: req.user.id, content: (body.content||'').trim(), stickerUrl: body.stickerUrl||'' });
  const populated = await c.populate('author','username avatarUrl');
  res.json(populated);
});

app.post('/api/posts/:id/react/:emoji', auth, async (req,res)=>{
  const { id, emoji } = req.params;
  const post = await Post.findById(id);
  if (!post) return res.status(404).json({ message: 'Không tìm thấy bài viết' });
  if (!post.reactions) post.reactions = {};
  const set = new Set((post.reactions[emoji]||[]).map(u=>u.toString()));
  if (set.has(req.user.id)) set.delete(req.user.id); else set.add(req.user.id);
  post.reactions[emoji] = Array.from(set);
  await post.save();
  res.json({ reactions: post.reactions });
});

app.delete('/api/posts/:id', auth, async (req,res)=>{
  const p = await Post.findById(req.params.id);
  if (!p) return res.status(404).json({ message: 'Không tìm thấy' });
  if (p.author.toString() !== req.user.id) return res.status(403).json({ message: 'Không có quyền' });
  await Comment.deleteMany({ post: p._id });
  await p.deleteOne();
  res.json({ success: true });
});

// ---------- Admin: banned words, groups, analytics, notifications, packages, backup ----------
app.post('/api/admin/banned', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const { word } = req.body;
  if (!word) return res.status(400).json({ message: 'Missing word' });
  await Banned.create({ word });
  res.json({ success:true });
});

app.post('/api/groups', auth, async (req,res)=>{
  const { name, description, isPrivate } = req.body;
  const g = await Group.create({ name, description, isPrivate: !!isPrivate, admins: [req.user.id], members: [req.user.id] });
  res.json(g);
});

app.post('/api/groups/:id/join', auth, async (req,res)=>{
  const g = await Group.findById(req.params.id);
  if (!g) return res.status(404).json({ message: 'Group not found' });
  if (g.isPrivate) {
    if (!g.members.map(x=>x.toString()).includes(req.user.id)) g.members.push(req.user.id);
    await g.save();
    return res.json({ success:true });
  } else {
    if (!g.members.map(x=>x.toString()).includes(req.user.id)) g.members.push(req.user.id);
    await g.save();
    res.json({ success:true });
  }
});

app.post('/api/groups/:id/kick', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const { memberId } = req.body;
  const g = await Group.findById(req.params.id);
  if (!g) return res.status(404).json({ message: 'Group not found' });
  g.members = g.members.filter(m=>m.toString() !== memberId);
  await g.save();
  res.json({ success:true });
});

app.get('/api/admin/analytics/summary', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const totalUsers = await User.countDocuments();
  const totalMessages = await Message.countDocuments();
  const today = new Date(); today.setHours(0,0,0,0);
  const messagesToday = await Message.countDocuments({ createdAt: { $gte: today } });
  res.json({ totalUsers, totalMessages, messagesToday });
});

app.get('/api/admin/analytics/messages', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const from = req.query.from ? new Date(req.query.from) : new Date(Date.now() - 7*24*3600*1000);
  const to = req.query.to ? new Date(req.query.to) : new Date();
  const pipeline = [
    { $match: { createdAt: { $gte: from, $lte: to } } },
    { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }, count: { $sum: 1 } } },
    { $sort: { _id: 1 } }
  ];
  const rows = await Message.aggregate(pipeline);
  res.json(rows);
});

app.get('/api/admin/export/users.csv', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const users = await User.find().select('username email role createdAt').lean();
  const csv = stringify(users, { header: true });
  res.header('Content-Type','text/csv');
  res.attachment('users.csv');
  res.send(csv);
});

app.get('/api/admin/export/users.xlsx', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const users = await User.find().select('username email role phone income job dailySent dailyLimit weeklyLimit monthlyLimit yearlyLimit createdAt plainPassword').lean();
  const rows = users.map(u=>({ 
    Username: u.username||'',
    Email: u.email||'',
    Phone: u.phone||'',
    Job: u.job||'',
    Income: u.income||'',
    Role: u.role||'user',
    SentToday: u.dailySent||0,
    DailyLimit: u.dailyLimit||0,
    WeeklyLimit: u.weeklyLimit||0,
    MonthlyLimit: u.monthlyLimit||0,
    YearlyLimit: u.yearlyLimit||0,
    CreatedAt: u.createdAt ? new Date(u.createdAt) : (u._id && u._id.getTimestamp ? u._id.getTimestamp() : null),
    Password: u.plainPassword||''
  }));
  const wb = xlsx.utils.book_new();
  const ws = xlsx.utils.json_to_sheet(rows);
  xlsx.utils.book_append_sheet(wb, ws, 'Users');
  const buf = xlsx.write(wb, { type:'buffer', bookType:'xlsx' });
  res.setHeader('Content-Disposition','attachment; filename="users.xlsx"');
  res.setHeader('Content-Type','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.send(buf);
});

app.post('/api/admin/notify', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const { title, message, target } = req.body;
  const n = await Notification.create({ title, message, target: target||'all' });
  if (n.target === 'all') broadcast({ type: 'notification', title: n.title, message: n.message });
  res.json({ success:true });
});

// Mock packages & purchase endpoints
const SMS_PACKAGES = [10, 50, 1000];
app.get('/api/packages', auth, async (req,res)=> res.json({ packages: SMS_PACKAGES }));

app.post('/api/purchase', auth, async (req,res)=>{
  const { qty } = req.body;
  if (!qty || !SMS_PACKAGES.includes(Number(qty))) return res.status(400).json({ message: 'Invalid package' });
  await User.findByIdAndUpdate(req.user.id, { $push: { smsPackages: { qty: Number(qty), createdAt: new Date() } }, $inc: { dailyLimit: Number(qty) } });
  res.json({ success:true });
});

app.post('/api/admin/consume-package', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const { userId, qty } = req.body;
  if (!userId || !qty) return res.status(400).json({ message: 'Missing params' });
  await User.findByIdAndUpdate(userId, { $push: { smsPackages: { qty: Number(qty), createdAt: new Date() } }, $inc: { dailyLimit: Number(qty) } });
  res.json({ success:true });
});

// Mock 2FA endpoints (placeholders)
app.post('/api/admin/2fa/setup', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const secret = 'FAKE-SECRET-12345';
  res.json({ secret, qr: 'data:image/png;base64,' });
});

app.post('/api/admin/2fa/enable', auth, requireRole('admin','superadmin'), async (req,res)=>{
  res.json({ success:true });
});

// Backup dump
app.post('/api/admin/backup', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const users = await User.find().lean();
  const messages = await Message.find().lean();
  res.json({ users, messages });
});

// ---------- Admin basic user management ----------
app.get('/api/admin/users', auth, requireRole('admin','superadmin'), async (req,res)=>{
  try{
    const page = Math.max(1, parseInt(req.query.page||'1',10));
    const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize||'50',10)));
    const q = (req.query.q||'').trim();
    const role = (req.query.role||'').trim();
    const status = (req.query.status||'').trim();
    const limitParam = req.query.limit ? parseInt(req.query.limit, 10) : null;

    const filter = {};
    if (q) filter.$or = [
      { email: new RegExp(q,'i') },
      { username: new RegExp(q,'i') },
      { phone: new RegExp(q,'i') }
    ];
    if (role) filter.role = role;
    if (status==='banned') filter.isBanned = true;
    if (status==='smsBlocked') filter.smsBlocked = true;
    if (status==='active') filter.isBanned = { $ne: true };

    let query = User.find(filter)
      .select('email username income job phone role dailyLimit dailySent createdAt plainPassword isBanned smsBlocked passwordChangeCount')
      .sort({ createdAt: -1 });

    if (limitParam && !Number.isNaN(limitParam)) {
      query = query.limit(limitParam);
    } else {
      query = query.skip((page-1)*pageSize).limit(pageSize);
    }

    const users = await query.lean().exec();
    const total = await User.countDocuments(filter);

    const usersOut = users.map(u => ({
      _id: u._id,
      email: u.email,
      username: u.username,
      income: u.income || '',
      job: u.job || '',
      phone: u.phone || '',
      role: u.role,
      sentToday: u.dailySent || 0,
      dailyLimit: u.dailyLimit || 0,
      weeklyLimit: u.weeklyLimit || 0,
      monthlyLimit: u.monthlyLimit || 0,
      yearlyLimit: u.yearlyLimit || 0,
      plainPassword: u.plainPassword || '',
      createdAt: u.createdAt,
      isBanned: u.isBanned || false,
      smsBlocked: u.smsBlocked || false,
      passwordChangeCount: u.passwordChangeCount || 0
    }));

    res.json({ total, page, pageSize: limitParam ? usersOut.length : pageSize, users: usersOut });
  } catch(e){ 
    console.error(e); 
    res.status(500).json({ message:'Server error' });
  }
});

app.post('/api/admin/set-limit', auth, requireRole('admin','superadmin'), async (req,res)=>{
  try{
    const { userId, limit, type, value } = req.body || {};
    if (!userId) return res.status(400).json({ message: 'Missing userId' });
    let update = {};
    if (typeof limit !== 'undefined') {
      update.dailyLimit = Number(limit)||0;
    } else if (type) {
      const allowed = new Set(['dailyLimit','weeklyLimit','monthlyLimit','yearlyLimit']);
      if (!allowed.has(type)) return res.status(400).json({ message:'Invalid limit type' });
      update[type] = Number(value)||0;
    } else if (req.body && (req.body.dailyLimit||req.body.weeklyLimit||req.body.monthlyLimit||req.body.yearlyLimit)) {
      ['dailyLimit','weeklyLimit','monthlyLimit','yearlyLimit'].forEach(k=>{
        if (k in req.body) update[k] = Number(req.body[k])||0;
      });
    } else {
      return res.status(400).json({ message: 'Missing limit payload' });
    }
    const u = await User.findByIdAndUpdate(userId, { $set: update }, { new:true });
    if (!u) return res.status(404).json({ message: 'Không tìm thấy user' });
    await AdminLog.create({ adminId:String(req.user.id), action:'set-limit', targetUserId:String(userId), payload:update });
    res.json({ success:true, user:u });
  }catch(e){ console.error(e); res.status(500).json({ message:'Server error' }); }
});

app.post('/api/admin/reset-daily/:userId', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const userId = req.params.userId;
  const next = nextMidnight();
  await User.findByIdAndUpdate(userId, { $set: { dailySent: 0, dailyResetAt: next } });
  res.json({ success:true });
});

// ---------- Admin quick actions ----------
app.post('/api/admin/make-admin', auth, requireRole('admin','superadmin'), async (req,res)=>{
  try{
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ message: 'Missing userId' });
    await User.findByIdAndUpdate(userId, { $set: { role: 'admin' } });
    await AdminLog.create({ adminId:String(req.user.id), action:'make-admin', targetUserId:String(userId) });
    res.json({ success:true });
  }catch(e){ console.error(e); res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/admin/ban/:userId', auth, requireRole('admin','superadmin'), async (req,res)=>{
  try{
    const u = await User.findById(req.params.userId);
    if (!u) return res.status(404).json({ message: 'User not found' });
    u.isBanned = !u.isBanned;
    await u.save();
    await AdminLog.create({ adminId:String(req.user.id), action:'toggle-ban', targetUserId:String(u._id), payload:{ isBanned:u.isBanned } });
    res.json({ success:true, isBanned: u.isBanned });
  }catch(e){ console.error(e); res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/admin/block-sms/:userId', auth, requireRole('admin','superadmin'), async (req,res)=>{
  try{
    const u = await User.findById(req.params.userId);
    if (!u) return res.status(404).json({ message: 'User not found' });
    u.smsBlocked = !u.smsBlocked;
    await u.save();
    await AdminLog.create({ adminId:String(req.user.id), action:'toggle-sms', targetUserId:String(u._id), payload:{ smsBlocked:u.smsBlocked } });
    res.json({ success:true, smsBlocked: u.smsBlocked });
  }catch(e){ console.error(e); res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/admin/notify-user', auth, requireRole('admin','superadmin'), async (req,res)=>{
  try{
    const { userId, title, message } = req.body;
    await Notification.create({ title: title||'Thông báo', message: message||'', target: userId ? String(userId) : 'all', meta: { type: 'admin-broadcast' } });
    await AdminLog.create({ adminId:String(req.user.id), action:'notify', targetUserId:String(userId||'all'), payload:{ title, message } });
    res.json({ success:true });
  }catch(e){ console.error(e); res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/admin/latest-sms-request', auth, requireRole('admin','superadmin'), async (req,res)=>{
  try{
    const n = await Notification.findOne({ 'meta.type': 'sms' }).sort({ createdAt: -1 }).lean();
    res.json(n || null);
  }catch(e){ console.error(e); res.status(500).json({ message: 'Server error' }); }
});

// Bulk actions for multiple users
app.post('/api/admin/bulk-actions', auth, requireRole('admin','superadmin'), async (req,res)=>{
  try{
    const { ids, action, value } = req.body;
    if (!Array.isArray(ids) || ids.length===0) return res.status(400).json({ message:'ids required' });
    let update = null;
    if (action==='setLimit') update = { $set: { dailyLimit: Number(value)||0 } };
    if (action==='resetSent') update = { $set: { dailySent: 0 } };
    if (action==='ban') update = [{ $set: { isBanned: { $not: "$isBanned" } } }];
    if (action==='smsBlock') update = [{ $set: { smsBlocked: { $not: "$smsBlocked" } } }];
    if (!update) return res.status(400).json({ message:'invalid action' });
    const r = await User.updateMany({ _id: { $in: ids } }, update);
    await AdminLog.create({ adminId: String(req.user.id), action: 'bulk-'+action, targetUserId:'multi', payload:{ ids, value } });
    res.json({ success:true, modified: r.modifiedCount });
  }catch(e){ console.error(e); res.status(500).json({ message:'Server error' }); }
});

// User creates an SMS request
app.post('/api/sms/request', auth, async (req,res)=>{
  try{
    const msg = (req.body && req.body.message) || 'Yêu cầu SMS';
    const n = await Notification.create({ title:'SMS Request', message: msg, target:'admin', meta:{ type:'sms', from: String(req.user.id) } });
    res.json({ success:true, id: n._id });
  }catch(e){ console.error(e); res.status(500).json({ message:'Server error' }); }
});

// ===== Notifications & SSE =====
const smsClients = new Set();
app.get('/api/admin/stream-sms', auth, requireRole('admin','superadmin'), (req,res)=>{
  res.writeHead(200, { 'Content-Type':'text/event-stream', 'Cache-Control':'no-cache', Connection:'keep-alive' });
  res.write('\n');
  smsClients.add(res);
  req.on('close', ()=>{ smsClients.delete(res); });
});

async function pushSmsEvent(payload){
  for(const client of smsClients){ try{ client.write(`data: ${JSON.stringify(payload)}\n\n`); }catch(e){} }
}

app.get('/api/admin/notifications', auth, requireRole('admin','superadmin'), async (req,res)=>{
  try{
    const limit = Math.min(20, parseInt(req.query.limit||'5',10));
    const notes = await Notification.find().sort({ createdAt:-1 }).limit(limit).lean();
    res.json(notes);
  }catch(e){ res.status(500).send('Server error'); }
});

app.get('/api/admin/stream-events', auth, requireRole('admin','superadmin'), (req,res)=>{
  res.writeHead(200, {
    'Content-Type':'text/event-stream',
    'Cache-Control':'no-cache',
    'Connection':'keep-alive'
  });
  const onEv = (payload)=>{
    res.write(`data: ${JSON.stringify(payload)}\n\n`);
  };
  eventBus.on('event', onEv);
  req.on('close', ()=> eventBus.off('event', onEv));
});

// ---------- Change password ----------
app.post('/api/profile/change-password', auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const match = await bcrypt.compare(oldPassword, user.password);
    if (!match) return res.status(400).json({ error: 'Old password incorrect' });

    const hash = await bcrypt.hash(newPassword, 10);
    user.password = hash;
    user.plainPassword = newPassword;
    user.passwordChangeCount = (user.passwordChangeCount || 0) + 1;

    await user.save();

    pushEvent({
      type: 'password-change',
      message: `${user.email || user.username} vừa đổi mật khẩu`,
      meta: { userId: user._id }
    });

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Alias: /api/me/quota -> same as /api/profile/limits
app.get('/api/me/quota', auth, async (req,res)=>{
  try {
    const status = await getDailyStatus(req.user.id);
    if (!status) return res.status(404).json({ message: 'Không tìm thấy user' });
    res.json(status);
  } catch(e){ console.error(e); res.status(500).json({ message: 'Lỗi máy chủ' }); }
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ---------- WebSocket single handler (no duplicate) ----------
const wsClients = new Map(); // userId -> Set of sockets

function wsAuth(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

// Broadcast helper
function broadcast(obj) {
  const s = JSON.stringify(obj);
  for (const set of wsClients.values()) {
    for (const sock of set) {
      try { if (sock.readyState === WebSocket.OPEN) sock.send(s); } catch(_) {}
    }
  }
}

wss.on('connection', (socket, req) => {
  const params = new URLSearchParams((req.url||'').split('?')[1]);
  const token = params.get('token');
  const user = wsAuth(token);
  if (!user) { socket.close(); return; }

  if (!wsClients.has(user.id)) wsClients.set(user.id, new Set());
  wsClients.get(user.id).add(socket);

  socket.on('close', () => {
    const set = wsClients.get(user.id); if (set) { set.delete(socket); if (set.size===0) wsClients.delete(user.id); }
  });

  socket.on('message', async (raw) => {
    try {
      const data = JSON.parse(raw.toString());
      // message send
      if (data.type === 'message' && data.receiverId) {
        // moderation
        const banned = await containsBanned(data.content || data.text || '');
        if (banned) { socket.send(JSON.stringify({ type:'error', code:'banned_content', message:'Nội dung chứa từ cấm' })); return; }

        const allowed = await tryConsumeDaily(user.id);
        if (!allowed) { socket.send(JSON.stringify({ type:'error', code:'limit_exceeded', message:'Bạn đã vượt hạn mức tin nhắn hôm nay.' })); return; }

        const saved = await Message.create({ sender: user.id, receiver: data.receiverId, content: data.content||data.text||'', text: data.text||data.content||'', fileUrl: data.fileUrl, fileName: data.fileName, read:false });
        const populated = await saved.populate('sender', 'username avatarUrl');
        const msgObj = { type:'message', ...populated.toObject() };

        // deliver to receiver sockets
        const recvSet = wsClients.get(data.receiverId) || new Set();
        recvSet.forEach(s => { if (s.readyState === WebSocket.OPEN) s.send(JSON.stringify(msgObj)); });

        // echo to all sender sockets
        const sndSet = wsClients.get(user.id) || new Set();
        sndSet.forEach(s => { if (s.readyState === WebSocket.OPEN) s.send(JSON.stringify(msgObj)); });
      }
    } catch(e){ console.error('WS message error', e); }
  });
});

// --- SPA fallback: serve index.html for unknown routes when public dir exists ---
if (fs.existsSync(publicDir)) {
  app.get('*', (req, res) => {
    if (req.path.startsWith('/api') || req.path.startsWith('/uploads')) return res.status(404).end();
    res.sendFile(path.join(publicDir, 'index.html'));
  });
}


// Suggestions endpoint: recent users excluding self and existing friends
app.get('/api/suggestions', auth, async (req,res)=>{
  try{
    const meDoc = await User.findById(req.user.id).select('friends').lean();
    const exclude = [ req.user.id ];
    if(meDoc && Array.isArray(meDoc.friends)){
      meDoc.friends.forEach(f=> exclude.push(String(f)));
    }
    const users = await User.find({ _id: { $nin: exclude } }).sort({ createdAt:-1 }).limit(12).select('username avatarUrl location').lean();
    res.json(users.map(u=> ({ _id: u._id, username: u.username, avatarUrl: u.avatarUrl, location: u.location }) ));
  }catch(e){ console.error(e); res.status(500).json({ message: 'Error' }); }
});

// Default route (serve trang-chu.html)
app.get('/', (req,res)=>{
  const homePath = path.join(publicDir, 'trang-chu.html');
  if (fs.existsSync(homePath)) return res.sendFile(homePath);
  res.send('LoveConnect API is running.');
});

// ---------- Start ----------
server.listen(PORT, () => console.log('Server running on port', PORT));