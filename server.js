require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;

// 🔥 CHỈ 1 KẾT NỐI MONGODB DUY NHẤT
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://datingappuser:Check68%40@cluster0.hsl2eh4.mongodb.net/dating-app?retryWrites=true&w=majority&appName=Cluster0';

console.log('🔄 Đang kết nối đến MongoDB...');
console.log('📝 URI:', MONGODB_URI.replace(/:[^:]*@/, ':****@'));

// 🔥 CHỈ 1 KẾT NỐI - KHÔNG TRÙNG LẶP
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('✅ Đã kết nối đến MongoDB thành công!');
    console.log('📊 Database:', mongoose.connection.name);
  })
  .catch(err => {
    console.log('❌ Lỗi kết nối MongoDB, sử dụng fallback mode...');
    console.log('💡 Lỗi:', err.message);
  });

// Middleware - CORS configuration
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

// Health check endpoint
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

// Dữ liệu tạm thời (fallback mode)
let users = [];
let posts = [];
let messages = [];
let nextId = 1;
let nextPostId = 1;
let nextMessageId = 1;

// Tạo user test mặc định trong fallback mode
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

// API Routes

// Đăng ký
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, profile } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Vui lòng điền đầy đủ thông tin' });
    }
    
    let existingUser;
    if (mongoose.connection.readyState === 1) {
      existingUser = await User.findOne({ $or: [{ username }, { email }] });
    } else {
      existingUser = users.find(u => u.username === username || u.email === email);
    }
    
    if (existingUser) {
      return res.status(400).json({ message: 'Tên đăng nhập hoặc email đã tồn tại' });
    }
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    if (mongoose.connection.readyState === 1) {
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

// Đăng nhập
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ message: 'Vui lòng điền đầy đủ thông tin' });
    }
    
    let user;
    if (mongoose.connection.readyState === 1) {
      user = await User.findOne({ $or: [{ username }, { email: username }] });
      
      if (user) {
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          user = null;
        }
      }
    } else {
      user = users.find(u => (u.username === username || u.email === username));
      
      if (user) {
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          user = null;
        }
      }
    }
    
    if (!user) {
      return res.status(400).json({ message: 'Tên đăng nhập hoặc mật khẩu không đúng' });
    }
    
    const token = jwt.sign(
      { userId: mongoose.connection.readyState === 1 ? user._id : user.id }, 
      process.env.JWT_SECRET || 'dating_app_secret_key_2025', 
      { expiresIn: '24h' }
    );
    
    res.json({ 
      token, 
      user: { 
        id: mongoose.connection.readyState === 1 ? user._id : user.id, 
        username: user.username,
        email: user.email,
        profile: user.profile
      },
      message: 'Đăng nhập thành công'
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Kiểm tra token
app.get('/api/check-auth', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    if (mongoose.connection.readyState === 1) {
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ 
          authenticated: false, 
          message: 'Người dùng không tồn tại' 
        });
      }
      
      res.json({ 
        authenticated: true, 
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          profile: user.profile
        }
      });
    } else {
      const user = users.find(u => u.id == userId);
      
      if (!user) {
        return res.status(404).json({ 
          authenticated: false, 
          message: 'Người dùng không tồn tại' 
        });
      }
      
      res.json({ 
        authenticated: true, 
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          profile: user.profile
        }
      });
    }
  } catch (error) {
    console.error('Check auth error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Lấy thông tin user
app.get('/api/user/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.params.id;
    
    if (mongoose.connection.readyState === 1) {
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: 'Không tìm thấy người dùng' });
      }
      
      const userWithoutPassword = user.toObject();
      delete userWithoutPassword.password;
      
      res.json(userWithoutPassword);
    } else {
      const user = users.find(u => u.id == userId);
      
      if (!user) {
        return res.status(404).json({ message: 'Không tìm thấy người dùng' });
      }
      
      const userWithoutPassword = { ...user };
      delete userWithoutPassword.password;
      
      res.json(userWithoutPassword);
    }
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Lấy danh sách user
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    
    if (mongoose.connection.readyState === 1) {
      const users = await User.find({}, '-password')
        .skip(skip)
        .limit(limit);
      
      const total = await User.countDocuments();
      
      res.json({
        users,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      });
    } else {
      const usersWithoutSensitiveInfo = users.map(user => {
        const { password, ...userWithoutPassword } = user;
        return userWithoutPassword;
      });
      
      const startIndex = skip;
      const endIndex = startIndex + limit;
      const paginatedUsers = usersWithoutSensitiveInfo.slice(startIndex, endIndex);
      
      res.json({
        users: paginatedUsers,
        pagination: {
          page,
          limit,
          total: users.length,
          pages: Math.ceil(users.length / limit)
        }
      });
    }
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Các API routes khác giữ nguyên...

// Route mặc định
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

// Xử lý lỗi
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Lỗi server không xác định', error: err.message });
});

// Khởi động server
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