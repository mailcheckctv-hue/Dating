require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const http = require('http');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/loveconnect';
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';

// ---------- DB ----------
mongoose.set('strictQuery', true);
mongoose.connect(MONGODB_URI);

const userSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String,
  gender: String,
  income: String,
  job: String,
  location: { type: String, default: 'Việt Nam' },
  avatarUrl: String,
  vip: { type: Boolean, default: false },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
}, { timestamps: true });

const postSchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  fileUrl: String,
  fileName: String,
  reactions: {
    like: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    heart: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    haha: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    wow: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    sad: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    angry: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  }
}, { timestamps: true });

const commentSchema = new mongoose.Schema({
  post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  stickerUrl: String,
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  fileUrl: String,
  fileName: String,
  stickerUrl: String,
  read: { type: Boolean, default: false },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Comment = mongoose.model('Comment', commentSchema);
const Message = mongoose.model('Message', messageSchema);

// ---------- Migration for old data ----------
async function migrateData(){
  try {
    await User.updateMany(
      { friends: { $exists: false } },
      { $set: { friends: [] } }
    );
    await User.updateMany(
      { vip: { $exists: false } },
      { $set: { vip: false } }
    );
    await Message.updateMany(
      { read: { $exists: false } },
      { $set: { read: false } }
    );
    console.log("Migration done");
  } catch (err){
    console.error("Migration error", err);
  }
}
migrateData();


// ---------- App ----------
const app = express();
const server = http.createServer(app);
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// static files
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
app.use('/uploads', express.static(uploadsDir));

const publicDir = path.join(__dirname, 'public');
if (fs.existsSync(publicDir)) app.use(express.static(publicDir));

// ---------- Multer ----------
const storage = multer.diskStorage({
  destination: function(req, file, cb){ cb(null, uploadsDir); },
  filename: function(req, file, cb){
    const safe = Date.now() + '-' + (file.originalname||'file').replace(/[^\w.\-]/g,'_');
    cb(null, safe);
  }
});
const upload = multer({ storage });

// ---------- Auth helper ----------
function auth(req, res, next){
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.substring(7) : null;
  if(!token) return res.status(401).json({ message: 'Missing token' });
  try{
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  }catch(e){
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// ---------- Auth routes ----------
app.post('/api/register', async (req, res) => {
  try{
    const { username, email, password, gender, income, job } = req.body;
    if(!email || !password) return res.status(400).json({ message: 'Thiếu thông tin' });
    const exists = await User.findOne({ email });
    if(exists) return res.status(400).json({ message: 'Email đã tồn tại' });
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ username, email, password: hash, gender, income, job });
    return res.json({ id: user._id });
  }catch(e){ console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

app.post('/api/login', async (req, res) => {
  try{
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if(!user) return res.status(400).json({ message: 'Sai email hoặc mật khẩu' });
    const ok = await bcrypt.compare(password, user.password);
    if(!ok) return res.status(400).json({ message: 'Sai email hoặc mật khẩu' });
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  }catch(e){ console.error(e); res.status(500).json({ message: 'Lỗi server' }); }
});

// ---------- Profile ----------
app.get('/api/profile', auth, async (req, res) => {
  const user = await User.findById(req.user.id).lean();
  res.json({ _id: user._id, id: user._id, username: user.username, email: user.email, avatarUrl: user.avatarUrl, location: user.location, vip: user.vip });
});

app.post('/api/profile/avatar', auth, upload.single('avatar'), async (req, res) => {
  if(!req.file) return res.status(400).json({ message: 'No file' });
  const url = `/uploads/${req.file.filename}`;
  await User.findByIdAndUpdate(req.user.id, { avatarUrl: url });
  res.json({ avatarUrl: url });
});

// ---------- Upload generic ----------
app.post('/api/upload', auth, upload.single('file'), async (req, res)=>{
  if(!req.file) return res.status(400).json({ message: 'No file' });
  const url = `/uploads/${req.file.filename}`;
  res.json({ fileUrl: url, fileName: req.file.originalname || req.file.filename });
});

// ---------- Posts ----------
app.post('/api/posts', auth, upload.single('file'), async (req, res) => {
  const p = await Post.create({
    author: req.user.id,
    content: req.body.content || '',
    fileUrl: req.file ? `/uploads/${req.file.filename}` : null,
    fileName: req.file ? (req.file.originalname || req.file.filename) : null
  });
  res.json(p);
});

app.get('/api/posts', auth, async (req, res) => {
  const list = await Post.find({}).sort({ createdAt: -1 }).populate('author', 'username avatarUrl').lean();
  res.json(list);
});

app.delete('/api/posts/:id', auth, async (req, res)=>{
  const p = await Post.findById(req.params.id);
  if(!p) return res.sendStatus(404);
  if(String(p.author) !== req.user.id) return res.sendStatus(403);
  await p.deleteOne();
  res.json({ ok: true });
});

app.post('/api/posts/:id/react/:emoji', auth, async (req, res) => {
  const allowed = ['like','heart','haha','wow','sad','angry'];
  const emoji = req.params.emoji;
  if(!allowed.includes(emoji)) return res.status(400).json({ message: 'emoji?'});
  const p = await Post.findById(req.params.id);
  if(!p) return res.sendStatus(404);
  // toggle
  allowed.forEach(k => {
    p.reactions[k] = p.reactions[k] || [];
    if(k === emoji){
      const idx = p.reactions[k].findIndex(id => String(id) === req.user.id);
      if(idx>=0) p.reactions[k].splice(idx,1);
      else p.reactions[k].push(req.user.id);
    }else{
      // remove from others (one type at a time)
      p.reactions[k] = p.reactions[k].filter(id => String(id)!==req.user.id);
    }
  });
  await p.save();
  res.json({ ok: true });
});

// Comments
app.get('/api/posts/:id/comments', auth, async (req, res)=>{
  const list = await Comment.find({ post: req.params.id }).sort({ createdAt: 1 }).populate('author','username avatarUrl').lean();
  res.json(list);
});
app.post('/api/posts/:id/comments', auth, async (req, res)=>{
  const { content, stickerUrl } = req.body;
  const c = await Comment.create({ post: req.params.id, author: req.user.id, content: content||'', stickerUrl });
  res.json(c);
});

// ---------- Friends (persisted) ----------
// Toggle friend: make mutual friendship (both sides). If already friends, keep as is.
app.post('/api/friends/:otherId', auth, async (req, res) => {
  const me = await User.findById(req.user.id);
  const other = await User.findById(req.params.otherId);
  if(!other) return res.sendStatus(404);
  const meHas = me.friends.some(id => String(id) === String(other._id));
  if(!meHas) me.friends.push(other._id);
  const otherHas = other.friends.some(id => String(id) === String(me._id));
  if(!otherHas) other.friends.push(me._id);
  await me.save(); await other.save();
  res.json({ ok: true });
});

// List friends (mutual)
app.get('/api/friends', auth, async (req,res)=>{
  const me = await User.findById(req.user.id).populate('friends','username avatarUrl').lean();
  // Only mutual friends
  const mutualIds = [];
  for(const f of me.friends){
    const u = await User.findById(f._id).lean();
    if(u && (u.friends||[]).map(id => String(id)).includes(String(req.user.id))) mutualIds.push(f._id);
  }
  const list = await User.find({ _id: { $in: mutualIds } }).select('username avatarUrl').lean();
  res.json(list.map(u => ({ _id: u._id, username: u.username, avatarUrl: u.avatarUrl })));
});

// Suggested users (not me, not already friend)
app.get('/api/users/suggested', auth, async (req, res)=>{
  const me = await User.findById(req.user.id).lean();
  const exclude = [req.user.id, ...(me.friends||[]).map(id => String(id))];
  const users = await User.find({ _id: { $nin: exclude } }).limit(20).select('username avatarUrl location').lean();
  res.json(users);
});

// ---------- Messages ----------
app.get('/api/messages/unread-count', auth, async (req, res)=>{
  const count = await Message.countDocuments({ receiver: req.user.id, read: false });
  res.json({ count });
});

app.get('/api/messages/total-count', auth, async (req, res)=>{
  const count = await Message.countDocuments({ $or: [{ sender: req.user.id }, { receiver: req.user.id }] });
  res.json({ count });
});

app.get('/api/messages/:otherId', auth, async (req, res) => {
  const otherId = req.params.otherId;
  const list = await Message.find({ 
    $or: [
      { sender: req.user.id, receiver: otherId },
      { sender: otherId, receiver: req.user.id }
    ]
  }).sort({ createdAt: 1 }).lean();
  res.json(list);
});

// mark read all from other
app.patch('/api/messages/read/:otherId', auth, async (req, res)=>{
  await Message.updateMany({ receiver: req.user.id, sender: req.params.otherId, read: false }, { $set: { read: true }});
  res.json({ ok: true });
});

// unread count
  const count = await Message.countDocuments({ receiver: req.user.id, read: false });
  res.json({ count });
});

// TOTAL message counter (diamond)
  const count = await Message.countDocuments({ 
    $or: [{ sender: req.user.id }, { receiver: req.user.id }]
  });
  res.json({ count });
});

// conversations (heads)
app.get('/api/conversations', auth, async (req, res)=>{
  const agg = await Message.aggregate([
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
    }}
  ]);
  const results = [];
  for(const g of agg){
    const other = await User.findById(g._id.other).lean();
    if(!other) continue;
    results.push({
      otherId: String(other._id),
      otherName: other.username,
      otherAvatar: other.avatarUrl,
      lastMessage: { content: g.lastMessage.content, fileName: g.lastMessage.fileName }
    });
  }
  res.json(results);
});

// upgrade VIP (mock)
app.post('/api/upgrade-vip', auth, async (req, res)=>{
  await User.findByIdAndUpdate(req.user.id, { vip: true });
  res.json({ ok: true });
});

// ---------- WebSocket for chat ----------
const wss = new WebSocketServer({ server });
const socketsByUser = new Map(); // userId -> Set<sockets>

function addSocket(userId, socket){
  if(!socketsByUser.has(userId)) socketsByUser.set(userId, new Set());
  socketsByUser.get(userId).add(socket);
  socket.on('close', ()=> socketsByUser.get(userId).delete(socket));
}

wss.on('connection', async (socket, req) => {
  // token from query ?token=...
  const url = new URL(req.url, 'http://localhost');
  const token = url.searchParams.get('token');
  try{
    const data = jwt.verify(token, JWT_SECRET);
    socket.user = { id: data.id };
    addSocket(data.id, socket);
  }catch(e){
    try { socket.close(); } catch(_){}
    return;
  }

  socket.on('message', async (raw)=>{
    try{
      const msg = JSON.parse(raw.toString());
      if(msg.type === 'message'){
        // VIP gate: only allow if sender is VIP or (optional) friends with receiver
        const sender = await User.findById(socket.user.id).lean();
        if(!sender.vip){
          socket.send(JSON.stringify({ type:'error', message:'Bạn cần mua gói VIP để nhắn tin.' }));
          return;
        }
        const saved = await Message.create({
          sender: socket.user.id,
          receiver: msg.receiverId,
          content: msg.content || '',
          fileUrl: msg.fileUrl || null,
          fileName: msg.fileName || null,
          stickerUrl: msg.stickerUrl || null
        });
        const payload = { type:'message', ...saved.toObject() };
        // send to receiver
        const recSet = socketsByUser.get(String(msg.receiverId)) || new Set();
        recSet.forEach(s => { if(s.readyState===1) s.send(JSON.stringify(payload)); });
        // echo back to sender
        const sndSet = socketsByUser.get(String(socket.user.id)) || new Set();
        sndSet.forEach(s => { if(s.readyState===1) s.send(JSON.stringify(payload)); });
      }
    }catch(e){ console.error('WS message error', e); }
  });
});

// ---------- Fallback ----------
app.get('/', (req, res)=>{
  if(fs.existsSync(path.join(publicDir,'login.html'))) res.sendFile(path.join(publicDir,'login.html'));
  else res.send('LoveConnect API');
});

server.listen(PORT, () => console.log('Server listening on', PORT));