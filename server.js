
/* LoveConnect server.js – full implementation for current frontend
   Features: Auth (JWT), Posts, Upload, Friends, Messaging + WebSocket, Profile avatar
*/
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { WebSocketServer } = require('ws');

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/loveconnect';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const PORT = process.env.PORT || 3000;

// ---- Mongo connection ----
mongoose.set('strictQuery', false);
mongoose.connect(MONGODB_URI).then(()=>{
  console.log('Mongo connected');
}).catch(err=>console.error('Mongo error', err));

// ---- Schemas ----
const userSchema = new mongoose.Schema({
  username: String,
  email: { type:String, unique:true },
  password: String,
  avatarUrl: String,
  gender: String,
  income: String,
  job: String,
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref:'User' }],
  isVIP: { type:Boolean, default:false },
  createdAt: { type: Date, default: Date.now }
});

const postSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref:'User' },
  content: String,
  mediaUrl: String,
  createdAt: { type: Date, default: Date.now },
  reactions: {
    like:   [{ type: mongoose.Schema.Types.ObjectId, ref:'User' }],
    heart:  [{ type: mongoose.Schema.Types.ObjectId, ref:'User' }],
    haha:   [{ type: mongoose.Schema.Types.ObjectId, ref:'User' }],
    wow:    [{ type: mongoose.Schema.Types.ObjectId, ref:'User' }],
    sad:    [{ type: mongoose.Schema.Types.ObjectId, ref:'User' }],
    angry:  [{ type: mongoose.Schema.Types.ObjectId, ref:'User' }],
  }
});

const messageSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref:'User' },
  to:   { type: mongoose.Schema.Types.ObjectId, ref:'User' },
  content: String,
  mediaUrl: String,
  createdAt: { type: Date, default: Date.now },
  read: { type:Boolean, default:false }
});

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Message = mongoose.model('Message', messageSchema);

// ---- Auth helpers ----
function signToken(u){ return jwt.sign({ id: u._id, email: u.email }, JWT_SECRET, { expiresIn: '7d' }); }
function auth(req,res,next){
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if(!token) return res.status(401).json({message:'No token'});
  try{ const d = jwt.verify(token, JWT_SECRET); req.userId = d.id; next(); }
  catch(e){ return res.status(401).json({message:'Invalid token'}); }
}

// ---- Multer for uploads ----
const uploadDir = path.join(__dirname, 'public', 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb)=> cb(null, uploadDir),
  filename: (req, file, cb)=> {
    const ext = path.extname(file.originalname) || '';
    cb(null, Date.now() + '-' + Math.random().toString(36).slice(2) + ext);
  }
});
const upload = multer({ storage });

// ---- Auth routes ----
app.post('/api/register', async (req,res)=>{
  try{
    const { username, email, password, gender, income, job } = req.body;
    if(!username || !email || !password) return res.status(400).json({message:'Thiếu thông tin'});
    const ex = await User.findOne({ email });
    if(ex) return res.status(400).json({message:'Email đã tồn tại'});
    const hash = await bcrypt.hash(password, 10);
    const u = await User.create({ username, email, password: hash, gender, income, job, friends:[] });
    res.json({ message:'OK' });
  }catch(e){ res.status(500).json({message:'Lỗi server'}); }
});

app.post('/api/login', async (req,res)=>{
  try{
    const { email, password } = req.body;
    const u = await User.findOne({ email });
    if(!u) return res.status(400).json({message:'Sai email hoặc mật khẩu'});
    const ok = await bcrypt.compare(password, u.password || '');
    if(!ok) return res.status(400).json({message:'Sai email hoặc mật khẩu'});
    res.json({ token: signToken(u) });
  }catch(e){ res.status(500).json({message:'Lỗi server'}); }
});

// ---- Profile ----
app.get('/api/profile', auth, async (req,res)=>{
  const u = await User.findById(req.userId).lean();
  res.json({ _id:u._id, username:u.username, email:u.email, avatarUrl:u.avatarUrl, isVIP:u.isVIP, gender:u.gender, income:u.income, job:u.job });
});

app.post('/api/profile/avatar', auth, upload.single('avatar'), async (req,res)=>{
  const fileUrl = '/uploads/' + path.basename(req.file.path);
  await User.findByIdAndUpdate(req.userId, { avatarUrl: fileUrl });
  res.json({ avatarUrl: fileUrl });
});

// ---- Upload generic ----
app.post('/api/upload', auth, upload.single('file'), async (req,res)=>{
  const fileUrl = '/uploads/' + path.basename(req.file.path);
  res.json({ url: fileUrl });
});

// ---- Posts ----
app.get('/api/posts', auth, async (req,res)=>{
  const me = await User.findById(req.userId);
  const ids = [me._id, ...me.friends];
  const posts = await Post.find({ user: { $in: ids } })
    .sort({ createdAt: -1 }).limit(100)
    .populate('user','username avatarUrl').lean();
  res.json(posts);
});

app.post('/api/posts', auth, async (req,res)=>{
  const { content, mediaUrl } = req.body;
  const p = await Post.create({ user:req.userId, content, mediaUrl, reactions:{} });
  const out = await Post.findById(p._id).populate('user','username avatarUrl').lean();
  res.json(out);
});

app.delete('/api/posts/:id', auth, async (req,res)=>{
  const p = await Post.findById(req.params.id);
  if(!p || p.user.toString() !== req.userId) return res.status(403).json({message:'Không có quyền'});
  await p.deleteOne();
  res.json({ ok:true });
});

app.post('/api/posts/:id/react', auth, async (req,res)=>{
  const { type } = req.body;
  const types = ['like','heart','haha','wow','sad','angry'];
  if(!types.includes(type)) return res.status(400).json({message:'Loại reaction không hợp lệ'});
  const p = await Post.findById(req.params.id);
  if(!p) return res.status(404).json({message:'Không tìm thấy bài viết'});
  // toggle
  types.forEach(t => { p.reactions[t] = p.reactions[t] || []; });
  const arr = p.reactions[type];
  const i = arr.findIndex(x => x.toString()===req.userId);
  if(i>=0) arr.splice(i,1); else arr.push(req.userId);
  await p.save();
  res.json({ ok:true });
});

// ---- Friends ----
app.get('/api/users/suggested', auth, async (req,res)=>{
  const me = await User.findById(req.userId).lean();
  const sug = await User.find({ _id: { $ne: me._id, $nin: me.friends || [] } })
        .select('username avatarUrl email').limit(10).lean();
  res.json(sug);
});

app.post('/api/friends/:id', auth, async (req,res)=>{
  const otherId = req.params.id;
  if(otherId===req.userId) return res.status(400).json({message:'Không thể tự kết bạn'});
  await User.findByIdAndUpdate(req.userId, { $addToSet: { friends: otherId } });
  await User.findByIdAndUpdate(otherId, { $addToSet: { friends: req.userId } });
  res.json({ ok:true });
});

app.get('/api/friends', auth, async (req,res)=>{
  const me = await User.findById(req.userId).populate('friends','username avatarUrl email').lean();
  res.json(me.friends || []);
});

// ---- Messaging ----
async function lastMessageBetween(a,b){
  return await Message.findOne({ $or:[ {from:a,to:b}, {from:b,to:a} ] }).sort({createdAt:-1}).lean();
}

app.get('/api/conversations', auth, async (req,res)=>{
  const myId = new mongoose.Types.ObjectId(req.userId);
  const pipeline = [
    { $match: { $or:[ {from: myId}, {to: myId} ] } },
    { $sort: { createdAt: -1 } },
    { $group: {
        _id: { $cond: [ { $eq: ['$from', myId] }, '$to', '$from' ] },
        last: { $first: '$$ROOT' },
        unread: { $sum: { $cond: [ { $and: [ { $eq: ['$to', myId] }, { $eq: ['$read', false] } ] }, 1, 0 ] } }
    } }
  ];
  const rows = await Message.aggregate(pipeline);
  const ids = rows.map(r=>r._id);
  const users = await User.find({ _id: { $in: ids } }).select('username avatarUrl').lean();
  const map = new Map(users.map(u=>[u._id.toString(),u]));
  const result = rows.map(r=>({ user: map.get(r._id.toString()), last: r.last, unread: r.unread }));
  res.json(result);
});

app.get('/api/messages/:userId', auth, async (req,res)=>{
  const other = req.params.userId;
  const msgs = await Message.find({ $or:[ {from:req.userId,to:other}, {from:other,to:req.userId} ] })
    .sort({ createdAt: -1 }).limit(100).lean();
  res.json(msgs.reverse());
});

app.post('/api/messages/:userId', auth, async (req,res)=>{
  const other = req.params.userId;
  const { content, mediaUrl } = req.body;
  const m = await Message.create({ from:req.userId, to:other, content, mediaUrl });
  // Push via WS
  pushToUser(other, { type:'message', sender: req.userId, content, mediaUrl, createdAt: m.createdAt });
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

// ---- VIP ----
app.post('/api/upgrade-vip', auth, async (req,res)=>{
  await User.findByIdAndUpdate(req.userId, { isVIP:true });
  res.json({ ok:true });
});

// ---- Serve pages ----
app.get('/', (req,res)=> res.sendFile(path.join(__dirname,'public','login.html')));

// ---- Start HTTP server ----
const server = app.listen(PORT, ()=> console.log('Server listening on', PORT));

// ---- WebSocket ----
const wss = new WebSocketServer({ server });
const sockets = new Map(); // userId -> ws

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const token = url.searchParams.get('token');
  let userId = null;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    userId = payload.id;
    sockets.set(userId, ws);
    ws.on('close', ()=> sockets.delete(userId));
  } catch(e){
    ws.close();
  }
});

function pushToUser(uid, payload){
  const ws = sockets.get(uid?.toString());
  if(ws && ws.readyState===1){
    if(payload.sender && typeof payload.sender === 'string'){
      // enrich sender
      User.findById(payload.sender).select('username avatarUrl').lean().then(u => {
        ws.send(JSON.stringify({ ...payload, sender: u }));
      }).catch(()=> ws.send(JSON.stringify(payload)));
    }else{
      ws.send(JSON.stringify(payload));
    }
  }
}
