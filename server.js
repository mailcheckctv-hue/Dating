
const path = require('path');
const fs = require('fs');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
const http = require('http').createServer(app);
const { Server } = require('socket.io');
const io = new Server(http, { cors: { origin: "*", methods: ["GET","POST"] } });

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname, 'public')));

const MONGODB_URI = process.env.MONGODB_URI;
mongoose.connect(MONGODB_URI, { })
  .then(()=>console.log('MongoDB connected'))
  .catch(err=>console.error('MongoDB error:', err.message));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g,'_'))
});
const upload = multer({ storage });

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  gender: { type: String, enum: ['Nam','Nữ','Khác'], default: 'Khác' },
  avatar: String,
  location: { type: String, default: 'Việt Nam' },
  role: { type: String, enum: ['user','admin'], default: 'user' },
  blocked: { type: Boolean, default: false },
}, { timestamps: true });

const postSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  image: String,
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  to: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  text: String,
  fileUrl: String,
  type: { type: String, enum: ['text', 'image', 'file'], default: 'text' },
  createdAt: { type: Date, default: Date.now },
  read: { type: Boolean, default: false }
});

const friendRequestSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  to: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: { type: String, enum: ['pending','accepted','rejected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const friendshipSchema = new mongoose.Schema({
  user1: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  user2: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Message = mongoose.model('Message', messageSchema);
const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);
const Friendship = mongoose.model('Friendship', friendshipSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
function signToken(user){ return jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '7d' }); }
function auth(req,res,next){
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if(!token) return res.status(401).json({ error:'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch(e){ return res.status(401).json({ error:'Invalid token' }); }
}
function adminOnly(req,res,next){ if(req.user?.role!=='admin') return res.status(403).json({ error:'Admin only' }); next(); }

const onlineUsers = new Map();
io.on('connection', (socket) => {
  socket.on('auth', (token) => {
    try{ const user = jwt.verify(token, JWT_SECRET); socket.userId=user.id; onlineUsers.set(user.id, socket.id); io.emit('presence',{userId:user.id,online:true}); }catch(e){}
  });
  socket.on('disconnect', ()=>{ if(socket.userId){ onlineUsers.delete(socket.userId); io.emit('presence',{userId:socket.userId,online:false}); } });
});

app.get('/api/health', (req,res)=>res.json({ ok:true }));

app.post('/api/auth/register', async (req,res)=>{
  try{
    const { name, email, password, gender } = req.body;
    const exists = await User.findOne({ email });
    if(exists) return res.status(400).json({ error:'Email đã tồn tại' });
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hash, gender });
    const token = signToken(user);
    res.json({ token, user: { id: user._id, name, email, gender, role: user.role } });
  }catch(e){ res.status(500).json({ error:'Đăng ký thất bại' }); }
});

app.post('/api/auth/login', async (req,res)=>{
  try{
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if(!user) return res.status(400).json({ error:'Sai thông tin đăng nhập' });
    if(user.blocked) return res.status(403).json({ error:'Tài khoản đã bị chặn' });
    const ok = await bcrypt.compare(password, user.password);
    if(!ok) return res.status(400).json({ error:'Sai thông tin đăng nhập' });
    const token = signToken(user);
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role, avatar: user.avatar } });
  }catch(e){ res.status(500).json({ error:'Đăng nhập thất bại' }); }
});

app.get('/api/profile', auth, async (req,res)=>{ const u = await User.findById(req.user.id).lean(); res.json(u); });

app.post('/api/users/avatar', auth, upload.single('avatar'), async (req,res)=>{
  const url = req.file ? `/uploads/${req.file.filename}` : null;
  await User.findByIdAndUpdate(req.user.id, { avatar: url });
  res.json({ avatar: url });
});

app.get('/api/users/suggested', auth, async (req,res)=>{
  const users = await User.find({ _id: { $ne: req.user.id }}).select('name avatar location gender').limit(12);
  res.json(users);
});

app.post('/api/posts', auth, upload.single('image'), async (req,res)=>{
  const post = await Post.create({ userId: req.user.id, content: req.body.content || '', image: req.file ? `/uploads/${req.file.filename}` : null });
  const populated = await Post.findById(post._id).populate('userId','name avatar email');
  res.json(populated);
});
app.get('/api/posts', auth, async (req,res)=>{
  const posts = await Post.find().sort({ createdAt: -1 }).limit(50).populate('userId','name avatar email');
  res.json(posts);
});

async function areFriends(a,b){
  const f = await Friendship.findOne({ $or: [{user1:a,user2:b},{user1:b,user2:a}] });
  return !!f;
}
app.post('/api/friends/request', auth, async (req,res)=>{
  const { to } = req.body;
  if(await areFriends(req.user.id,to)) return res.status(400).json({ error:'Đã là bạn bè' });
  const exists = await FriendRequest.findOne({ from:req.user.id, to, status:'pending' });
  if(exists) return res.status(400).json({ error:'Đã gửi lời mời' });
  const fr = await FriendRequest.create({ from:req.user.id, to });
  res.json(fr);
});
app.post('/api/friends/accept', auth, async (req,res)=>{
  const { requestId } = req.body;
  const fr = await FriendRequest.findById(requestId);
  if(!fr || String(fr.to)!==req.user.id) return res.status(400).json({ error:'Không hợp lệ' });
  fr.status = 'accepted'; await fr.save();
  await Friendship.create({ user1: fr.from, user2: fr.to });
  res.json({ ok:true });
});
app.get('/api/friends/list', auth, async (req,res)=>{
  const f1 = await Friendship.find({ user1:req.user.id }).populate('user2','name avatar email');
  const f2 = await Friendship.find({ user2:req.user.id }).populate('user1','name avatar email');
  const list = f1.map(x=>x.user2).concat(f2.map(x=>x.user1));
  res.json(list);
});

app.get('/api/messages/unread-count', auth, async (req,res)=>{
  const cnt = await Message.countDocuments({ to: req.user.id, read:false });
  res.json({ count: cnt });
});
app.get('/api/messages/thread', auth, async (req,res)=>{
  const { userId } = req.query;
  const msgs = await Message.find({ $or:[{from:req.user.id,to:userId},{from:userId,to:req.user.id}] }).sort({ createdAt:1 });
  res.json(msgs);
});
app.post('/api/messages/send', auth, upload.single('file'), async (req,res)=>{
  const { to, text, type } = req.body;
  const friends = await areFriends(req.user.id, to);
  if(!friends) return res.status(403).json({ error:'Chỉ nhắn khi đã là bạn bè' });
  const msg = await Message.create({ from: req.user.id, to, text: text || '', type: req.file ? (type || 'file') : (type || 'text'), fileUrl: req.file ? `/uploads/${req.file.filename}` : null });
  const receiverSocket = onlineUsers.get(String(to));
  if(receiverSocket){ io.to(receiverSocket).emit('message:new', msg); }
  res.json(msg);
});

app.get('/api/admin/messages', auth, (req,res,next)=>{ if(req.user?.role!=='admin') return res.status(403).json({error:'Admin only'}); next(); }, async (req,res)=>{
  const msgs = await Message.find().sort({ createdAt:-1 }).limit(200); res.json(msgs);
});
app.post('/api/admin/block/:userId', auth, async (req,res)=>{
  if(req.user?.role!=='admin') return res.status(403).json({error:'Admin only'});
  await User.findByIdAndUpdate(req.params.userId, { blocked: true }); res.json({ ok:true });
});
app.post('/api/admin/unblock/:userId', auth, async (req,res)=>{
  if(req.user?.role!=='admin') return res.status(403).json({error:'Admin only'});
  await User.findByIdAndUpdate(req.params.userId, { blocked: false }); res.json({ ok:true });
});
app.delete('/api/admin/users/:userId', auth, async (req,res)=>{
  if(req.user?.role!=='admin') return res.status(403).json({error:'Admin only'});
  await User.findByIdAndDelete(req.params.userId); res.json({ ok:true });
});

app.get('/', (req,res)=> res.sendFile(path.join(__dirname,'public','login.html')));
app.get('/login.html', (req,res)=> res.sendFile(path.join(__dirname,'public','login.html')));
app.get('/dang-ky.html', (req,res)=> res.sendFile(path.join(__dirname,'public','dang-ky.html')));
app.get('/trang-chu.html', (req,res)=> res.sendFile(path.join(__dirname,'public','trang-chu.html')));

const PORT = process.env.PORT || 5000;
http.listen(PORT, ()=> console.log('Server running on port', PORT));
