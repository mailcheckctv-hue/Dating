require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;
const HOST = '0.0.0.0';

// ==================== MONGODB CONNECTION ====================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://datingappuser:95485675@cluster0.hsl2eh4.mongodb.net/dating-app?retryWrites=true&w=majority&appName=Cluster0';

console.log('🔄 Đang kết nối đến MongoDB...');

mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('✅ Đã kết nối đến MongoDB thành công!');
    console.log('📊 Database:', mongoose.connection.name);
  })
  .catch(err => {
    console.log('❌ Lỗi kết nối MongoDB:', err.message);
    console.log('⚠️  Ứng dụng sẽ chạy ở chế độ fallback (bộ nhớ)');
  });

// ==================== MIDDLEWARE ====================
app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// ==================== SCHEMAS & MODELS ====================
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profile: {
    fullname: String,
    age: Number,
    gender: { type: String, enum: ['Nam', 'Nữ', 'Khác'] },
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

// ==================== FALLBACK DATA ====================
let users = [];
let posts = [];
let messages = [];
let nextId = 1;

// ==================== AUTH MIDDLEWARE ====================
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

// ==================== API ROUTES ====================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Server is working!',
    timestamp: new Date().toISOString(),
    port: PORT
  });
});

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, confirmPassword, profile } = req.body;
    
    if (!username || !email || !password || !confirmPassword) {
      return res.status(400).json({ message: 'Vui lòng điền đầy đủ thông tin' });
    }
    
    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Mật khẩu xác nhận không khớp' });
    }
    
    // Kiểm tra user tồn tại
    let existingUser;
    if (mongoose.connection.readyState === 1) {
      existingUser = await User.findOne({ $or: [{ username }, { email }] });
    } else {
      existingUser = users.find(u => u.username === username || u.email === email);
    }
    
    if (existingUser) {
      return res.status(400).json({ message: 'Tên đăng nhập hoặc email đã tồn tại' });
    }
    
    // Mã hóa password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    if (mongoose.connection.readyState === 1) {
      // MongoDB mode
      const newUser = new User({
        username,
        email,
        password: hashedPassword,
        profile: profile || {},
        friends: []
      });
      
      await newUser.save();
      
      const token = jwt.sign(
        { userId: newUser._id }, 
        process.env.JWT_SECRET || 'dating_app_secret_key_2025', 
        { expiresIn: '24h' }
      );
      
      res.status(201).json({ 
        message: 'Đăng ký thành công',
        token,
        user: {
          id: newUser._id,
          username: newUser.username,
          email: newUser.email,
          profile: newUser.profile
        }
      });
    } else {
      // Fallback mode
      const newUser = {
        id: nextId++,
        username,
        email,
        password: hashedPassword,
        profile: profile || {},
        friends: [],
        createdAt: new Date()
      };
      
      users.push(newUser);
      
      const token = jwt.sign(
        { userId: newUser.id }, 
        process.env.JWT_SECRET || 'dating_app_secret_key_2025', 
        { expiresIn: '24h' }
      );
      
      res.status(201).json({ 
        message: 'Đăng ký thành công',
        token,
        user: {
          id: newUser.id,
          username: newUser.username,
          email: newUser.email,
          profile: newUser.profile
        }
      });
    }
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Login endpoint - ĐÃ ĐƯỢC THÊM VÀO
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    console.log('Login attempt:', { email });
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Vui lòng điền email và mật khẩu' });
    }
    
    let user;
    if (mongoose.connection.readyState === 1) {
      // MongoDB mode
      user = await User.findOne({ $or: [{ email }, { username: email }] });
      if (user) {
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
          user = null;
        }
      }
    } else {
      // Fallback mode
      user = users.find(u => u.email === email || u.username === email);
      if (user) {
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
          user = null;
        }
      }
    }
    
    if (!user) {
      return res.status(400).json({ message: 'Email hoặc mật khẩu không đúng' });
    }
    
    const token = jwt.sign(
      { userId: mongoose.connection.readyState === 1 ? user._id : user.id }, 
      process.env.JWT_SECRET || 'dating_app_secret_key_2025', 
      { expiresIn: '24h' }
    );
    
    res.json({ 
      message: 'Đăng nhập thành công',
      token,
      user: {
        id: mongoose.connection.readyState === 1 ? user._id : user.id,
        username: user.username,
        email: user.email,
        profile: user.profile
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get current user
app.get('/api/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    if (mongoose.connection.readyState === 1) {
      const user = await User.findById(userId).select('-password');
      if (!user) return res.status(404).json({ message: 'User not found' });
      res.json(user);
    } else {
      const user = users.find(u => u.id == userId);
      if (!user) return res.status(404).json({ message: 'User not found' });
      const { password, ...userWithoutPassword } = user;
      res.json(userWithoutPassword);
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get all users
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    if (mongoose.connection.readyState === 1) {
      const users = await User.find().select('-password');
      res.json(users);
    } else {
      const usersWithoutPassword = users.map(({ password, ...user }) => user);
      res.json(usersWithoutPassword);
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Create post
app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { content, image } = req.body;
    const userId = req.user.userId;
    
    if (!content) {
      return res.status(400).json({ message: 'Content is required' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const post = new Post({
        userId,
        content,
        image: image || '',
        likes: [],
        comments: []
      });
      
      const savedPost = await post.save();
      const populatedPost = await Post.findById(savedPost._id).populate('userId', 'username profile');
      res.status(201).json(populatedPost);
    } else {
      const post = {
        id: nextId++,
        userId,
        content,
        image: image || '',
        likes: [],
        comments: [],
        createdAt: new Date()
      };
      
      posts.push(post);
      res.status(201).json(post);
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get all posts
app.get('/api/posts', authenticateToken, async (req, res) => {
  try {
    if (mongoose.connection.readyState === 1) {
      const posts = await Post.find().populate('userId', 'username profile').sort({ createdAt: -1 });
      res.json(posts);
    } else {
      res.json(posts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Update profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { fullname, age, gender, bio, interests, avatar } = req.body;
    
    if (mongoose.connection.readyState === 1) {
      const user = await User.findById(userId);
      if (!user) return res.status(404).json({ message: 'User not found' });
      
      user.profile = { fullname, age, gender, bio, interests, avatar };
      await user.save();
      
      res.json({ message: 'Profile updated successfully', profile: user.profile });
    } else {
      const user = users.find(u => u.id == userId);
      if (!user) return res.status(404).json({ message: 'User not found' });
      
      user.profile = { fullname, age, gender, bio, interests, avatar };
      res.json({ message: 'Profile updated successfully', profile: user.profile });
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// ==================== STATIC ROUTES ====================
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

// ==================== ERROR HANDLING ====================
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Lỗi server không xác định', error: err.message });
});

// ==================== START SERVER ====================
app.listen(PORT, HOST, () => {
  console.log(`=== SERVER DATING APP ===`);
  console.log(`🚀 Server đang chạy trên ${HOST}:${PORT}`);
  console.log(`🌍 Môi trường: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📁 Phục vụ file tĩnh từ: ${path.join(__dirname, 'public')}`);
  console.log(`================================`);
});