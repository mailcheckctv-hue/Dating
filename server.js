
require('dotenv').config();
const path = require('path');
const fs = require('fs');
const http = require('http');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 10000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/loveconnect';
const JWT_SECRET = process.env.JWT_SECRET || 'change_me';

// ---------- App & Server ----------
const app = express();
app.use(cors());
app.use(express.json({ limit:'5mb' }));

const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOAD_DIR = path.join(PUBLIC_DIR, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive:true });

app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static(PUBLIC_DIR));

// ---------- DB ----------
mongoose.set('strictQuery', false);
mongoose.connect(MONGODB_URI, { dbName:'loveconnect' }).then(()=>{
  console.log('Mongo connected');
}).catch(e=> console.error('Mongo error', e.message));

// ---------- Schemas ----------
const userSchema = new mongoose.Schema({
  username: String,
  email: { type:String, unique:true },
  password: String,
  gender: String,
  avatarUrl: String,
  income: String,
  job: String,
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref:'User' }],
  isVIP: { type:Boolean, default:false }
}, { timestamps:true });

const postSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref:'User' },
  content: String,
  mediaUrl: String,
  createdAt: { type: Date, default: Date.now },
  reactions: {
    like:  [{ type: mongoose.Schema.Types.ObjectId, ref:'User' }],
    heart: [{ type: mongoose.Schema.Types.ObjectId, ref:'User' }],
    haha:  [{ type: mongoose.Schema.Types.ObjectId, ref:'User' }],
    wow:   [{ type: mongoose.Schema.Types.ObjectId, ref:'User' }],
    sad:   [{ type: mongoose.Schema.Types.ObjectId, ref:'User' }],
    angry: [{ type: mongoose.Schema.Types.ObjectId, ref:'User' }],
  }
});

const messageSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref:'User' },
  to:   { type: mongoose.Schema.Types.ObjectId, ref:'User' },
  content: String,
  mediaUrl: String,
  read: { type:Boolean, default:false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Message = mongoose.model('Message', messageSchema);

// ---------- Auth Helpers ----------
function signToken(user){ return jwt.sign({ id:user._id, email:user.email }, JWT_SECRET, { expiresIn:'7d' }); }
function auth(req,res,next){
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if(!token) return res.status(401).json({ message:'No token' });
  try{ const p = jwt.verify(token, JWT_SECRET); req.userId = p.id; next(); }
  catch(e){ return res.status(401).json({ message:'Invalid token' }); }
}

// ---------- Upload (multer) ----------
const storage = multer.diskStorage({
  destination: (_, __, cb)=> cb(null, UPLOAD_DIR),
  filename: (_, file, cb)=> {
    const ext = path.extname(file.originalname || '');
    const name = Date.now() + '-' + Math.random().toString(36).slice(2) + ext;
    cb(null, name);
  }
});
const upload = multer({ storage });

// ---------- Routes ----------
app.get('/healthz', (_,res)=> res.json({ ok:true }));

// Auth
app.post('/api/register', async (req,res)=>{
  try{
    const { username, email, password, gender } = req.body;
    if(!username || !email || !password) return res.status(400).json({ message:'Thiếu dữ liệu' });
    const ex = await User.findOne({ email });
    if(ex) return res.status(400).json({ message:'Email đã tồn tại' });
    const hash = await bcrypt.hash(password, 10);
    const u = await User.create({ username, email, password: hash, gender });
    return res.json({ token: signToken(u) });
  }catch(e){ return res.status(500).json({ message:'Lỗi máy chủ' }); }
});

app.post('/api/login', async (req,res)=>{
  try{
    const { email, password } = req.body;
    const u = await User.findOne({ email });
    if(!u) return res.status(400).json({ message:'Sai email hoặc mật khẩu' });
    const ok = await bcrypt.compare(password, u.password || '');
    if(!ok) return res.status(400).json({ message:'Sai email hoặc mật khẩu' });
    return res.json({ token: signToken(u) });
  }catch(e){ return res.status(500).json({ message:'Lỗi máy chủ' }); }
});

// Profile
app.get('/api/profile', auth, async (req,res)=>{
  const u = await User.findById(req.userId).lean();
  res.json({ _id:u._id, username:u.username, email:u.email, avatarUrl:u.avatarUrl, isVIP:u.isVIP });
});
app.post('/api/profile/avatar', auth, upload.single('avatar'), async (req,res)=>{
  const url = '/uploads/' + req.file.filename;
  await User.findByIdAndUpdate(req.userId, { avatarUrl: url });
  res.json({ avatarUrl: url });
});

// Upload (generic for post/media)
app.post('/api/upload', auth, upload.single('file'), (req,res)=>{
  const url = '/uploads/' + req.file.filename;
  res.json({ url });
});

// Posts
app.get('/api/posts', auth, async (req,res)=>{
  const me = await User.findById(req.userId);
  const ids = [me._id, ...(me.friends||[])];
  const posts = await Post.find({ user: { $in: ids } })
    .sort({ createdAt:-1 }).limit(100)
    .populate('user','username avatarUrl').lean();
  res.json(posts);
});
app.post('/api/posts', auth, async (req,res)=>{
  const { content, mediaUrl } = req.body;
  const p = await Post.create({ user:req.userId, content, mediaUrl });
  const out = await Post.findById(p._id).populate('user','username avatarUrl').lean();
  res.json(out);
});
app.delete('/api/posts/:id', auth, async (req,res)=>{
  const p = await Post.findById(req.params.id);
  if(!p || p.user.toString() !== req.userId) return res.status(403).json({ message:'Không có quyền' });
  await p.deleteOne();
  res.json({ ok:true });
});
app.post('/api/posts/:id/react', auth, async (req,res)=>{
  const types = ['like','heart','haha','wow','sad','angry'];
  const { type } = req.body;
  if(!types.includes(type)) return res.status(400).json({ message:'Loại reaction không hợp lệ' });
  const p = await Post.findById(req.params.id);
  if(!p) return res.status(404).json({ message:'Không tìm thấy bài viết' });
  p.reactions = p.reactions || {};
  types.forEach(t => p.reactions[t] = p.reactions[t] || []);
  const arr = p.reactions[type];
  const i = arr.findIndex(x => x.toString()===req.userId);
  if(i>=0) arr.splice(i,1); else arr.push(req.userId);
  await p.save();
  res.json({ ok:true });
});

// Friends
app.get('/api/users/suggested', auth, async (req,res)=>{
  const me = await User.findById(req.userId).lean();
  const sug = await User.find({ _id: { $ne: me._id, $nin: me.friends||[] } })
              .select('username email avatarUrl').limit(10).lean();
  res.json(sug);
});
app.post('/api/friends/:id', auth, async (req,res)=>{
  const other = req.params.id;
  await User.findByIdAndUpdate(req.userId, { $addToSet: { friends: other } });
  await User.findByIdAndUpdate(other, { $addToSet: { friends: req.userId } });
  res.json({ ok:true });
});
app.get('/api/friends', auth, async (req,res)=>{
  const me = await User.findById(req.userId).populate('friends','username avatarUrl email').lean();
  res.json(me.friends || []);
});

// Messages
app.get('/api/messages/:userId', auth, async (req,res)=>{
  const other = req.params.userId;
  const msgs = await Message.find({ $or:[ {from:req.userId,to:other}, {from:other,to:req.userId} ] })
                .sort({ createdAt:-1 }).limit(100).lean();
  res.json(msgs.reverse());
});
app.post('/api/messages/:userId', auth, async (req,res)=>{
  const other = req.params.userId;
  const { content, mediaUrl } = req.body;
  const m = await Message.create({ from:req.userId, to:other, content, mediaUrl });
  pushToUser(other, { type:'message', sender: await userLite(req.userId), receiver: other, content, fileUrl: mediaUrl, createdAt: m.createdAt });
  res.json(m);
});
app.get('/api/messages/unread-count', auth, async (req,res)=>{
  const c = await Message.countDocuments({ to:req.userId, read:false });
  res.json({ count:c });
});
app.post('/api/messages/read/:userId', auth, async (req,res)=>{
  const other = req.params.userId;
  await Message.updateMany({ from:other, to:req.userId, read:false }, { $set:{ read:true } });
  res.json({ ok:true });
});

// VIP
app.post('/api/upgrade-vip', auth, async (req,res)=>{
  await User.findByIdAndUpdate(req.userId, { isVIP:true });
  res.json({ ok:true });
});

// ---------- Serve root ----------
app.get('/', (_,res)=> res.sendFile(path.join(PUBLIC_DIR, 'login.html')));

// ---------- Start HTTP ----------
const httpServer = http.createServer(app);
const wss = new WebSocketServer({ server: httpServer });
const sockets = new Map(); // userId -> ws

function userLite(id){ return User.findById(id).select('username avatarUrl').lean(); }

wss.on('connection', (ws, req) => {
  try{
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');
    const payload = jwt.verify(token, JWT_SECRET);
    const uid = payload.id.toString();
    sockets.set(uid, ws);
    ws.on('close', ()=> sockets.delete(uid));
  }catch(e){ ws.close(); }
});

function pushToUser(uid, payload){
  const ws = sockets.get(uid?.toString());
  if(ws && ws.readyState === ws.OPEN){
    ws.send(JSON.stringify(payload));
  }
}

httpServer.listen(PORT, ()=> console.log('Server listening on', PORT));
