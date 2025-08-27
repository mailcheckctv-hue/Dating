const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { WebSocketServer } = require('ws');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// ===== Ensure uploads folder exists =====
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads', { recursive: true });
}

// ===== Middlewares =====
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Serve static html files from project root
app.use(express.static(path.join(__dirname)));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// ===== DB Connection =====
const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URI;
if (!mongoUri) {
  console.error("❌ Missing MONGO_URI / MONGODB_URI in environment variables");
  process.exit(1);
}
mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB error:", err));

// ===== Schemas =====
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  gender: String,
  avatar: String,
  vip: { type: String, default: 'free' },
});
const messageSchema = new mongoose.Schema({
  sender: String,
  receiver: String,
  content: String,
  fileUrl: String,
  fileName: String,
  createdAt: { type: Date, default: Date.now }
});
const postSchema = new mongoose.Schema({
  userId: String,
  content: String,
  image: String,
  video: String,
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const Post = mongoose.model('Post', postSchema);

// ===== Auth Middleware =====
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// ===== File Upload =====
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
  res.json({ fileUrl: '/uploads/' + req.file.filename, fileName: req.file.originalname });
});

// ===== Auth Routes =====
app.post('/api/register', async (req, res) => {
  const { username, email, password, gender } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ username, email, password: hashed, gender });
  await user.save();
  res.json({ message: 'User registered' });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'User not found' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid password' });
  const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET);
  res.json({ token });
});

// ===== Posts API =====
app.get('/api/posts', authenticateToken, async (req, res) => {
  const posts = await Post.find().sort({ createdAt: -1 }).limit(50);
  res.json(posts);
});
app.post('/api/posts', authenticateToken, upload.single('file'), async (req, res) => {
  let image, video;
  if (req.file) {
    if (req.file.mimetype.startsWith('image')) image = '/uploads/' + req.file.filename;
    if (req.file.mimetype.startsWith('video')) video = '/uploads/' + req.file.filename;
  }
  const post = new Post({ userId: req.user.id, content: req.body.content, image, video });
  await post.save();
  res.json(post);
});

// ===== Suggestions API =====
app.get('/api/users/suggested', authenticateToken, async (req, res) => {
  const users = await User.find().limit(10);
  res.json(users);
});

// ===== WebSocket =====
let clients = {};
wss.on('connection', (ws, req) => {
  const params = new URLSearchParams(req.url.replace('/?', ''));
  const token = params.get('token');
  if (!token) return ws.close();
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return ws.close();
    ws.userId = user.id;
    clients[user.id] = ws;

    ws.on('message', async msg => {
      const data = JSON.parse(msg);
      if (data.type === 'message') {
        const newMsg = new Message({
          sender: ws.userId,
          receiver: data.receiverId,
          content: data.content,
          fileUrl: data.fileUrl,
          fileName: data.fileName
        });
        await newMsg.save();
        if (clients[data.receiverId]) {
          clients[data.receiverId].send(JSON.stringify({ type: 'message', message: newMsg }));
        }
        ws.send(JSON.stringify({ type: 'message', message: newMsg }));
      }
    });

    ws.on('close', () => delete clients[user.id]);
  });
});

// ===== Start =====
const PORT = process.env.PORT || 10000;
server.listen(PORT, () => console.log('Server running on port ' + PORT));
