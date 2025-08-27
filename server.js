
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET","POST","PUT","DELETE"] }
});

// ---------- Middleware ----------
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Ensure uploads folder
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// Multer for uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g,'_'))
});
const upload = multer({ storage });

// ---------- Mongoose ----------
mongoose.set('strictQuery', false);
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error("Missing MONGODB_URI in env");
}

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  avatarUrl: { type: String, default: "/uploads/default-avatar.png" },
  role: { type: String, enum: ["user","admin"], default: "user" },
  blocked: { type: Boolean, default: false },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  friendRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }], // incoming
}, { timestamps: true });

const postSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  content: { type: String },
  imageUrl: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  content: { type: String },
  type: { type: String, enum: ["text","image","file"], default: "text" },
  fileUrl: { type: String },
  createdAt: { type: Date, default: Date.now },
  read: { type: Boolean, default: false }
});

const User = mongoose.model("User", userSchema);
const Post = mongoose.model("Post", postSchema);
const Message = mongoose.model("Message", messageSchema);

// ---------- Auth Helpers ----------
function signToken(user) {
  return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "7d" });
}
function auth(req,res,next){
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if(!token) return res.status(401).json({ error: "Missing token" });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}
function authAdmin(req,res,next){
  if(!req.user || req.user.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  next();
}

// ---------- Socket.IO ----------
const onlineUsers = new Map(); // userId -> socket.id
io.on("connection", (socket) => {
  socket.on("join", (userId) => {
    onlineUsers.set(userId, socket.id);
    socket.join(userId);
    io.emit("onlineList", Array.from(onlineUsers.keys()));
  });
  socket.on("disconnect", () => {
    for (const [uid, sid] of onlineUsers.entries()) {
      if (sid === socket.id) onlineUsers.delete(uid);
    }
    io.emit("onlineList", Array.from(onlineUsers.keys()));
  });
});

// ---------- Routes: Auth ----------
app.post("/api/register", async (req,res) => {
  try{
    const { username, email, password } = req.body;
    if(!username || !email || !password) return res.status(400).json({ error: "Thiếu dữ liệu" });
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ error: "Email đã được sử dụng" });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ username, email, password: hashed });
    const token = signToken(user);
    res.json({ token, user: { id:user._id, username, email, role:user.role, avatarUrl:user.avatarUrl } });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

app.post("/api/login", async (req,res) => {
  try{
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if(!user) return res.status(400).json({ error: "Không tìm thấy người dùng" });
    if(user.blocked) return res.status(403).json({ error: "Tài khoản đã bị chặn" });
    const ok = await bcrypt.compare(password, user.password);
    if(!ok) return res.status(400).json({ error: "Mật khẩu không đúng" });
    const token = signToken(user);
    res.json({ token, user: { id:user._id, username:user.username, email:user.email, role:user.role, avatarUrl:user.avatarUrl } });
  }catch(e){ res.status(500).json({ error: e.message }); }
});

app.get("/api/profile/me", auth, async (req,res)=>{
  const me = await User.findById(req.user.id).select("-password");
  res.json(me);
});

// ---------- Avatar Upload ----------
app.post("/api/avatar", auth, upload.single("avatar"), async (req,res)=>{
  const url = "/uploads/" + req.file.filename;
  await User.findByIdAndUpdate(req.user.id, { avatarUrl: url });
  res.json({ avatarUrl: url });
});

// ---------- Posts ----------
app.post("/api/posts", auth, upload.single("image"), async (req,res)=>{
  try{
    const imageUrl = req.file ? "/uploads/" + req.file.filename : (req.body.imageUrl || null);
    const post = await Post.create({ user: req.user.id, content: req.body.content || "", imageUrl });
    const out = await Post.findById(post._id).populate("user","username avatarUrl");
    res.json(out);
  }catch(e){ res.status(500).json({ error: e.message }); }
});
app.get("/api/posts", auth, async (req,res)=>{
  const posts = await Post.find().sort({ createdAt: -1 }).populate("user","username avatarUrl");
  res.json(posts);
});

// ---------- Friends ----------
app.get("/api/users/suggested", auth, async (req,res)=>{
  // gợi ý những user không phải là bạn và không phải chính mình
  const me = await User.findById(req.user.id);
  const exclude = [req.user.id, ...me.friends, ...me.friendRequests];
  const list = await User.find({ _id: { $nin: exclude } }).select("username avatarUrl").limit(10);
  res.json(list);
});

app.post("/api/friends/request/:id", auth, async (req,res)=>{
  if(req.params.id === req.user.id) return res.status(400).json({ error: "Không thể tự kết bạn" });
  const target = await User.findById(req.params.id);
  if(!target) return res.status(404).json({ error: "Không tìm thấy user" });
  if (target.friendRequests.includes(req.user.id) || target.friends.includes(req.user.id)) {
    return res.status(400).json({ error: "Đã gửi lời mời hoặc đã là bạn" });
  }
  target.friendRequests.push(req.user.id);
  await target.save();
  res.json({ ok: true });
});

app.post("/api/friends/accept/:id", auth, async (req,res)=>{
  const requesterId = req.params.id;
  const me = await User.findById(req.user.id);
  if(!me.friendRequests.includes(requesterId)) return res.status(400).json({ error: "Không có lời mời" });
  me.friendRequests = me.friendRequests.filter(x => x.toString() !== requesterId);
  me.friends.push(requesterId);
  await me.save();
  const other = await User.findById(requesterId);
  if(!other.friends.includes(req.user.id)) {
    other.friends.push(req.user.id);
    await other.save();
  }
  res.json({ ok: true });
});

app.get("/api/friends", auth, async (req,res)=>{
  const me = await User.findById(req.user.id).populate("friends","username avatarUrl");
  res.json(me.friends || []);
});

// ---------- Messages ----------
app.post("/api/messages", auth, upload.single("file"), async (req,res)=>{
  try{
    const { receiver, content, type } = req.body;
    const fileUrl = req.file ? "/uploads/" + req.file.filename : null;
    const msg = await Message.create({
      sender: req.user.id, receiver, content: content || "", type: type || (fileUrl ? "file" : "text"), fileUrl
    });
    const populated = await Message.findById(msg._id).populate("sender receiver","username avatarUrl");
    // emit to receiver
    io.to(receiver).emit("newMessage", populated);
    res.json(populated);
  }catch(e){ res.status(500).json({ error: e.message }); }
});

app.get("/api/messages/with/:userId", auth, async (req,res)=>{
  const other = req.params.userId;
  const list = await Message.find({
    $or: [
      { sender: req.user.id, receiver: other },
      { sender: other, receiver: req.user.id }
    ]
  }).sort({ createdAt: 1 });
  res.json(list);
});

app.get("/api/messages/unread-count", auth, async (req,res)=>{
  const counts = await Message.aggregate([
    { $match: { receiver: new mongoose.Types.ObjectId(req.user.id), read: false } },
    { $group: { _id: "$sender", total: { $sum: 1 } } }
  ]);
  res.json(counts);
});

app.post("/api/messages/mark-read/:userId", auth, async (req,res)=>{
  const other = req.params.userId;
  await Message.updateMany({ sender: other, receiver: req.user.id, read:false }, { $set:{ read:true }});
  res.json({ ok: true });
});

// ---------- Admin ----------
app.get("/api/admin/users", auth, authAdmin, async (req,res)=>{
  const users = await User.find().select("-password");
  res.json(users);
});

app.get("/api/admin/messages", auth, authAdmin, async (req,res)=>{
  const msgs = await Message.find().sort({ createdAt:-1 }).limit(500).populate("sender receiver","username email");
  res.json(msgs);
});

app.put("/api/admin/block/:id", auth, authAdmin, async (req,res)=>{
  const u = await User.findById(req.params.id);
  if(!u) return res.status(404).json({ error: "User not found" });
  u.blocked = !u.blocked;
  await u.save();
  res.json({ blocked: u.blocked });
});

app.delete("/api/admin/delete/:id", auth, authAdmin, async (req,res)=>{
  await User.findByIdAndDelete(req.params.id);
  await Message.deleteMany({ $or: [{ sender: req.params.id }, { receiver: req.params.id }] });
  await Post.deleteMany({ user: req.params.id });
  res.json({ ok: true });
});

// ---------- Static ----------
app.use("/uploads", express.static(uploadDir));
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req,res)=> res.sendFile(path.join(__dirname, "public", "login.html")));

// ---------- DB connect & seed ----------
async function seedIfEmpty(){
  const count = await User.countDocuments();
  if (count > 0) return;

  // Create admin
  const admin = await User.create({
    username: "Admin CFC",
    email: "admincheck@loveconnect.com",
    password: await bcrypt.hash("432674", 10),
    role: "admin",
    avatarUrl: "https://i.pravatar.cc/150?img=5"
  });

  // Create sample users
  const users = [];
  for (let i=1; i<=5; i++){
    users.push(await User.create({
      username: "User"+i,
      email: `user${i}@mail.com`,
      password: await bcrypt.hash("123456", 10),
      avatarUrl: `https://i.pravatar.cc/150?img=${10+i}`
    }));
  }

  // Posts with image urls
  const imgUrls = [
    "https://images.unsplash.com/photo-1517817748496-62f0ec4f1a49?q=80&w=1080&auto=format&fit=crop",
    "https://images.unsplash.com/photo-1544006659-f0b21884ce1d?q=80&w=1080&auto=format&fit=crop",
    "https://images.unsplash.com/photo-1520975922284-9bcd373a2e2d?q=80&w=1080&auto=format&fit=crop"
  ];
  for (let i=0; i<3; i++){
    await Post.create({ user: users[i]._id, content: "Xin chào LoveConnect! #" + (i+1), imageUrl: imgUrls[i] });
  }

  // Seed messages between user1 and user2
  await Message.create({ sender: users[0]._id, receiver: users[1]._id, content: "Chào bạn, kết bạn nhé?" });
  await Message.create({ sender: users[1]._id, receiver: users[0]._id, content: "Ok bạn ơi!" });
}

mongoose.connect(MONGODB_URI).then(async() => {
  console.log("Mongo connected");
  await seedIfEmpty();
}).catch(err => console.error("Mongo error:", err.message));

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => console.log("Server running on port", PORT));
