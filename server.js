require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
console.log('🔄 Đang kết nối đến MongoDB...');
console.log('📝 URI from env:', process.env.MONGODB_URI ? 'Exists' : 'Missing');
console.log('📝 Using URI:', MONGODB_URI.replace(/:[^:]*@/, ':****@'));

const app = express();
const PORT = process.env.PORT || 10000;

// ✅ URI MỚI VỚI PASSWORD 95485675 (không cần encode)
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://datingappuser:95485675@cluster0.hsl2eh4.mongodb.net/dating-app?retryWrites=true&w=majority&appName=Cluster0';

console.log('🔄 Đang kết nối đến MongoDB...');
console.log('📝 URI:', MONGODB_URI.replace(/:[^:]*@/, ':****@'));

// ✅ KẾT NỐI MONGODB DUY NHẤT
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('✅ Đã kết nối đến MongoDB thành công!');
    console.log('📊 Database:', mongoose.connection.name);
  })
  .catch(err => {
    console.log('❌ Lỗi kết nối MongoDB, sử dụng fallback mode...');
    console.log('💡 Lỗi:', err.message);
  });

// Middleware
app.use(cors({
  origin: function(origin, callback) {
    callback(null, true);
  },
  credentials: true,
  optionsSuccessStatus: 200
}));

app.options('*', cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Middleware logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Server is working!',
    timestamp: new Date().toISOString(),
    port: PORT
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    usingFallback: mongoose.connection.readyState !== 1,
    environment: process.env.NODE_ENV || 'development'
  });
});

// Schema và Model
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profile: {
    fullname: String,
    age: Number,
    gender: String,
    bio: String,
    interests: [String],
    avatar: String
  },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const PostSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  image: String,
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    content: String,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiverId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const Message = mongoose.model('Message', MessageSchema);

// Fallback data
let users = [];
let posts = [];
let messages = [];
let nextId = 1;
let nextPostId = 1;
let nextMessageId = 1;

// Tạo user test fallback
if (mongoose.connection.readyState !== 1 && users.length === 0) {
  console.log('👤 Tạo tài khoản test trong fallback mode...');
  
  const createTestUser = async () => {
    try {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash('123456', salt);
      
      users.push({
        id: 1,
        username: 'demo1',
        email: 'demo1@example.com',
        password: hashedPassword,
        profile: {
          fullname: 'Người Dùng Demo',
          age: 25,
          gender: 'Khác',
          bio: 'Đây là tài khoản demo',
          interests: ['test', 'demo'],
          avatar: ''
        },
        friends: [],
        createdAt: new Date()
      });
      
      console.log('✅ Đã tạo tài khoản test: demo1 / 123456');
    } catch (error) {
      console.error('❌ Lỗi tạo user test:', error);
    }
  };
  
  createTestUser();
}

// Middleware xác thực JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Token truy cập không tồn tại' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'dating_app_secret_key_2025', (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Token không hợp lệ' });
    }
    
    req.user = decoded;
    next();
  });
};

// API Routes (giữ nguyên các API endpoints từ code trước)
// ... [giữ nguyên tất cả các API endpoints] ...

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/trang-chu', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'trang-chu.html'));
});

app.get('/dang-ky', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dang-ky.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Lỗi server không xác định', error: err.message });
});

// Start server
app.listen(PORT, () => {
  console.log(`=== SERVER DATING APP ===`);
  console.log(`🚀 Server đang chạy trên port ${PORT}`);
  console.log(`🌍 Môi trường: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Kết nối MongoDB: ${mongoose.connection.readyState === 1 ? '✅ Thành công' : '❌ Thất bại'}`);
  if (mongoose.connection.readyState !== 1) {
    console.log(`🔧 Đang sử dụng chế độ fallback với tài khoản test: demo1 / 123456`);
  }
  console.log(`📁 Phục vụ file tĩnh từ: ${path.join(__dirname, 'public')}`);
  console.log(`================================`);
});