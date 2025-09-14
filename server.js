const User = require('./models/User');

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
const MONGO =
  process.env.MONGODB_URI ||
  process.env.MONGO_URL ||
  process.env.MONGO_URI ||
  'mongodb://127.0.0.1:27017/loveconnect';
const ADMIN_RESET_SECRET = process.env.ADMIN_RESET_SECRET || '';

// Connect Mongo
mongoose
  .connect(MONGO, { dbName: 'loveconnect' })
  .then(async () => {
    console.log('MongoDB connected');
    try {
      await ensureDefaultAdmin();
    } catch (e) {
      console.error('ensureDefaultAdmin error', e);
    }
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
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname || '');
    cb(null, unique + ext);
  },
});
const upload = multer({ storage });

// ---------- Schemas ----------
const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    gender: { type: String, enum: ['Nam', 'Nữ', 'Khác'], default: 'Khác' },
    avatarUrl: String,
    location: String,
    vip: {
      type: String,
      enum: ['none', 'vip-week', 'basic', 'premium'],
      default: 'none',
    },
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    role: {
      type: String,
      enum: ['guest', 'user', 'moderator', 'admin', 'superadmin'],
      default: 'user',
    },
    dailyLimit: { type: Number, default: 5 },
    dailySent: { type: Number, default: 0 },
    dailyResetAt: {
      type: Date,
      default: () => {
        const d = new Date();
        d.setHours(24, 0, 0, 0);
        return d;
      },
    },
    isLocked: { type: Boolean, default: false },
    smsPackages: [{ qty: Number, createdAt: Date }],
  },
  { timestamps: true }
);

const postSchema = new mongoose.Schema(
  {
    reactions: { type: Object, default: {} },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: String,
    fileUrl: String,
    fileName: String,
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  },
  { timestamps: true }
);

const messageSchema = new mongoose.Schema(
  {
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: String,
    text: String,
    fileUrl: String,
    fileName: String,
    read: { type: Boolean, default: false },
  },
  { timestamps: true }
);

const groupSchema = new mongoose.Schema(
  {
    name: String,
    slug: String,
    description: String,
    isPrivate: { type: Boolean, default: false },
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    admins: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    moderators: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    messageLimitPerDay: { type: Number, default: 1000 },
  },
  { timestamps: true }
);

const bannedSchema = new mongoose.Schema({ word: String }, { timestamps: true });
const notificationSchema = new mongoose.Schema(
  {
    title: String,
    message: String,
    target: String,
    meta: Object,
  },
  { timestamps: true }
);
const twoFASchema = new mongoose.Schema(
  { user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, secret: String, enabled: Boolean },
  { timestamps: true }
);

const Post = mongoose.model('Post', postSchema);
const Message = mongoose.model('Message', messageSchema);
const Group = mongoose.model('Group', groupSchema);
const Banned = mongoose.model('Banned', bannedSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const TwoFA = mongoose.model('TwoFA', twoFASchema);

// ---------- Helpers ----------
function signToken(user) {
  return jwt.sign({ id: user._id, email: user.email, username: user.username }, JWT_SECRET, {
    expiresIn: '7d',
  });
}

// ✅ Hàm publicUser fix
function publicUser(user) {
  if (!user) return null;
  return {
    id: user._id,
    username: user.username,
    email: user.email,
    avatarUrl: user.avatarUrl || '',
    role: user.role || 'user',
    createdAt: user.createdAt,
  };
}
// ---------- Middlewares ----------
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

async function ensureDefaultAdmin() {
  try {
    const USERNAME = 'Admin_Check_1';
    const PLAIN = '87787323';
    const EMAIL = 'admin_check_1@local';
    let existing = await User.findOne({ $or: [{ username: USERNAME }, { email: EMAIL }] });
    if (!existing) {
      const hash = await bcrypt.hash(PLAIN, 10);
      const admin = new User({ username: USERNAME, email: EMAIL, password: hash, role: 'admin', dailyLimit: 999999 });
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
  await User.updateOne({ _id: userId, dailyResetAt: { $lte: now } }, { $set: { sentToday: 0, dailyResetAt: next } });
}

async function tryConsumeDaily(userId) {
  await resetIfNeeded(userId);
  const user = await User.findById(userId).lean();
  if (!user) return false;
  if (['admin','superadmin'].includes(user.role)) return true;
  const updated = await User.findOneAndUpdate({ _id: userId, dailySent: { $lt: user.dailyLimit } }, { $inc: { dailySent: 1 } }, { new: true });
  return !!updated;
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
    res.json({ token, user: { id: user._id, username: user.username, email: user.email } });
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
// ---------- Admin APIs ----------
app.get('/api/admin/users', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const users = await User.find().lean();
  res.json(users.map(u=>publicUser(u)));
});

app.get('/api/admin/export/csv', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const users = await User.find().lean();
  const records = users.map(u => [u._id, u.username, u.email, u.role, u.createdAt]);
  const csv = stringify(records, { header: true, columns: ['id','username','email','role','createdAt'] });
  res.setHeader('Content-disposition', 'attachment; filename=users.csv');
  res.set('Content-Type', 'text/csv');
  res.send(csv);
});

app.get('/api/admin/export/xlsx', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const users = await User.find().lean();
  const ws = xlsx.utils.json_to_sheet(users.map(u=>({ id: u._id.toString(), username: u.username, email: u.email, role: u.role })));
  const wb = xlsx.utils.book_new();
  xlsx.utils.book_append_sheet(wb, ws, 'Users');
  const buf = xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });
  res.setHeader('Content-disposition', 'attachment; filename=users.xlsx');
  res.set('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.send(buf);
});

app.post('/api/admin/notify', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const { title, message, target } = req.body;
  await Notification.create({ title, message, target });
  pushEvent({ type:'admin-notify', message, meta:{ title, target } });
  res.json({ success:true });
});

app.get('/api/admin/banned', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const list = await Banned.find().lean();
  res.json(list);
});
app.post('/api/admin/banned', auth, requireRole('admin','superadmin'), async (req,res)=>{
  const { word } = req.body;
  if (!word) return res.status(400).json({ message: 'Missing word' });
  const banned = await Banned.create({ word });
  res.json(banned);
});
app.delete('/api/admin/banned/:id', auth, requireRole('admin','superadmin'), async (req,res)=>{
  await Banned.findByIdAndDelete(req.params.id);
  res.json({ success:true });
});

// ---------- SSE ----------
function pushEvent(payload) {
  eventBus.emit('event', payload);
}
app.get('/api/admin/stream-events', auth, requireRole('admin','superadmin'), (req,res)=>{
  res.writeHead(200, {
    'Content-Type':'text/event-stream',
    'Cache-Control':'no-cache',
    'Connection':'keep-alive'
  });
  const onEv = (payload)=>{ res.write(`data: ${JSON.stringify(payload)}\n\n`); };
  eventBus.on('event', onEv);
  req.on('close', ()=> eventBus.off('event', onEv));
});

// ---------- Change Password ----------
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

// ---------- WebSocket Chat ----------
const wsClients = new Map(); // userId -> ws
wss.on('connection', (ws, req)=>{
  const params = new URLSearchParams(req.url.replace(/^.*\?/, ''));
  const token = params.get('token');
  if (!token) return ws.close();
  let user=null;
  try { user = jwt.verify(token, JWT_SECRET); } catch(e){ return ws.close(); }
  ws.user = user;
  wsClients.set(user.id, ws);

  ws.on('message', async (msg)=>{
    try {
      const data = JSON.parse(msg.toString());
      if (data.type==='chat' && data.to && data.text) {
        if (await containsBanned(data.text)) { ws.send(JSON.stringify({ type:'error', message:'Nội dung chứa từ cấm' })); return; }
        if (!(await tryConsumeDaily(user.id))) { ws.send(JSON.stringify({ type:'error', message:'Đã vượt hạn mức tin nhắn hôm nay' })); return; }
        const m = await Message.create({ sender: user.id, receiver: data.to, text: data.text });
        const payload = { type:'chat', from: user.id, to: data.to, text: data.text, createdAt: m.createdAt };
        if (wsClients.has(data.to)) wsClients.get(data.to).send(JSON.stringify(payload));
        ws.send(JSON.stringify(payload));
      }
    } catch(e){ console.error('WS message error', e); }
  });

  ws.on('close', ()=> wsClients.delete(user.id));
});

// ---------- Fallback ----------
app.get('*', (req,res)=>{
  res.sendFile(path.join(publicDir, 'trang-chu.html'));
});

// ---------- Start ----------
server.listen(PORT, ()=> console.log('🚀 Server running on port', PORT));
