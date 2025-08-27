require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const WebSocket = require('ws');
const http = require('http');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 10000;
const HOST = '0.0.0.0';

// ==================== MONGODB CONNECTION ====================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://datingappuser:95485675@cluster0.hsl2eh4.mongodb.net/dating-app?retryWrites=true&w=majority&appName=Cluster0';

console.log('🔄 Đang kết nối đến MongoDB...');

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ Đã kết nối đến MongoDB thành công!');
})
.catch(err => {
  console.log('❌ Lỗi kết nối MongoDB:', err.message);
});

// ==================== MIDDLEWARE QUAN TRỌNG ====================
app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.options('*', cors());

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// SERVING STATIC FILES - FIX QUAN TRỌNG
app.use(express.static(path.join(__dirname, 'public'), {
  index: 'login.html',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Content-Type', 'text/html; charset=UTF-8');
    }
  }
}));

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
    avatar: String,
    location: String,
    income: String
  },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  matches: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  isVip: { type: Boolean, default: false },
  vipType: { type: String, enum: ['none', 'week', 'basic', 'premium'], default: 'none' },
  vipExpiry: Date,
  createdAt: { type: Date, default: Date.now }
});

const PostSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: String,
  image: String,
  video: String,
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    content: String,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const MessageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const NotificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, required: true }, // 'friend_request', 'message', 'vip_approved', 'admin'
  content: { type: String, required: true },
  isRead: { type: Boolean, default: false },
  relatedId: mongoose.Schema.Types.ObjectId, // ID of related user/post/message
  createdAt: { type: Date, default: Date.now }
});

const VIPRequestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  planType: { type: String, enum: ['week', 'basic', 'premium'], required: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  paymentProof: String, // URL to payment proof image
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const Message = mongoose.model('Message', MessageSchema);
const Notification = mongoose.model('Notification', NotificationSchema);
const VIPRequest = mongoose.model('VIPRequest', VIPRequestSchema);

// ==================== FALLBACK DATA ====================
let users = [];
let nextId = 1;

// ==================== EMAIL CONFIGURATION ====================
const transporter = nodemailer.createTransporter({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'mailcheckctv@gmail.com',
    pass: process.env.EMAIL_PASS || 'your_email_password'
  }
});

// ==================== WEBSOCKET CONNECTIONS ====================
const clients = new Map();

wss.on('connection', (ws, req) => {
  const urlParams = new URLSearchParams(req.url.split('?')[1]);
  const userId = urlParams.get('userId');
  
  if (userId) {
    clients.set(userId, ws);
    console.log(`User ${userId} connected via WebSocket`);
  }
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
      }
      
      // Handle other message types as needed
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  });
  
  ws.on('close', () => {
    if (userId) {
      clients.delete(userId);
      console.log(`User ${userId} disconnected from WebSocket`);
    }
  });
});

// Function to send notification via WebSocket
function sendNotification(userId, notification) {
  const client = clients.get(userId);
  if (client && client.readyState === WebSocket.OPEN) {
    client.send(JSON.stringify({
      type: 'notification',
      data: notification
    }));
  }
}

// ==================== RESET PASSWORD HANDLING ====================
const resetCodes = new Map();

function generateResetCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function sendResetCode(email, code) {
  console.log(`Mã xác nhận cho ${email}: ${code}`);
  
  // Send email with reset code
  const mailOptions = {
    from: process.env.EMAIL_USER || 'mailcheckctv@gmail.com',
    to: email,
    subject: 'Mã xác nhận đặt lại mật khẩu - LoveConnect',
    html: `
      <h2>Mã xác nhận đặt lại mật khẩu</h2>
      <p>Mã xác nhận của bạn là: <strong>${code}</strong></p>
      <p>Mã này có hiệu lực trong 15 phút.</p>
      <p>Nếu bạn không yêu cầu đặt lại mật khẩu, vui lòng bỏ qua email này.</p>
    `
  };
  
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending email:', error);
    } else {
      console.log('Email sent:', info.response);
    }
  });
  
  return true;
}

// ==================== API ROUTES ====================

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.json({ 
    status: 'OK', 
    message: 'Server đang hoạt động',
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.json({ 
    message: 'Kết nối thành công! Server đang hoạt động.',
    timestamp: new Date().toISOString()
  });
});

// Verify token endpoint
app.get('/api/verify-token', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ valid: false, message: 'Token không hợp lệ' });
    }
    
    const token = authHeader.substring(7);
    
    // Xác thực token
    jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key', (err, decoded) => {
      if (err) {
        return res.status(401).json({ valid: false, message: 'Token không hợp lệ hoặc đã hết hạn' });
      }
      
      res.json({ valid: true, userId: decoded.userId });
    });
  } catch (error) {
    console.error('Verify token error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ valid: false, message: 'Lỗi server', error: error.message });
  }
});

// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
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
        friends: [],
        matches: []
      });
      
      await newUser.save();
      
      const token = jwt.sign(
        { userId: newUser._id }, 
        process.env.JWT_SECRET || 'fallback_secret_key', 
        { expiresIn: '24h' }
      );
      
      res.status(201).json({ 
        message: 'Đăng ký thành công',
        token,
        user: {
          id: newUser._id,
          username: newUser.username,
          email: newUser.email,
          profile: newUser.profile,
          isVip: newUser.isVip
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
        matches: [],
        isVip: false,
        createdAt: new Date()
      };
      
      users.push(newUser);
      
      const token = jwt.sign(
        { userId: newUser.id }, 
        process.env.JWT_SECRET || 'fallback_secret_key', 
        { expiresIn: '24h' }
      );
      
      res.status(201).json({ 
        message: 'Đăng ký thành công (fallback mode)',
        token,
        user: {
          id: newUser.id,
          username: newUser.username,
          email: newUser.email,
          profile: newUser.profile,
          isVip: newUser.isVip
        }
      });
    }
  } catch (error) {
    console.error('Register error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ message: 'Vui lòng điền đầy đủ thông tin' });
    }
    
    let user;
    if (mongoose.connection.readyState === 1) {
      user = await User.findOne({ $or: [{ username }, { email: username }] });
      if (user && !(await bcrypt.compare(password, user.password))) {
        user = null;
      }
    } else {
      user = users.find(u => u.username === username || u.email === username);
      if (user && !(await bcrypt.compare(password, user.password))) {
        user = null;
      }
    }
    
    if (!user) {
      return res.status(400).json({ message: 'Tên đăng nhập hoặc mật khẩu không đúng' });
    }
    
    const token = jwt.sign(
      { userId: mongoose.connection.readyState === 1 ? user._id : user.id }, 
      process.env.JWT_SECRET || 'fallback_secret_key', 
      { expiresIn: '24h' }
    );
    
    res.json({ 
      token, 
      user: { 
        id: mongoose.connection.readyState === 1 ? user._id : user.id, 
        username: user.username,
        email: user.email,
        profile: user.profile,
        isVip: user.isVip
      },
      message: 'Đăng nhập thành công'
    });
  } catch (error) {
    console.error('Login error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Admin login endpoint
app.post('/api/admin/login', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ message: 'Vui lòng điền đầy đủ thông tin' });
    }
    
    // Check admin credentials
    if (username === 'Admin_CFC' && password === '687969') {
      const token = jwt.sign(
        { userId: 'admin', isAdmin: true }, 
        process.env.JWT_SECRET || 'fallback_secret_key', 
        { expiresIn: '24h' }
      );
      
      res.json({ 
        token, 
        user: { 
          id: 'admin',
          username: 'Admin_CFC',
          isAdmin: true
        },
        message: 'Đăng nhập admin thành công'
      });
    } else {
      res.status(401).json({ message: 'Thông tin đăng nhập admin không đúng' });
    }
  } catch (error) {
    console.error('Admin login error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Forgot password endpoint
app.post('/api/forgot-password', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: 'Vui lòng cung cấp email' });
    }
    
    let user;
    if (mongoose.connection.readyState === 1) {
      user = await User.findOne({ email });
    } else {
      user = users.find(u => u.email === email);
    }
    
    if (!user) {
      return res.status(404).json({ message: 'Email không tồn tại trong hệ thống' });
    }
    
    // Tạo mã xác nhận
    const resetCode = generateResetCode();
    const expiresAt = Date.now() + 15 * 60 * 1000; // 15 phút
    
    // Lưu mã xác nhận
    resetCodes.set(email, { code: resetCode, expiresAt });
    
    // Gửi mã
    const sent = sendResetCode(email, resetCode);
    
    if (sent) {
      res.json({ 
        message: 'Mã xác nhận đã được gửi đến email của bạn',
        expiresIn: '15 phút'
      });
    } else {
      res.status(500).json({ message: 'Không thể gửi mã xác nhận' });
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Verify reset code endpoint
app.post('/api/verify-reset-code', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { email, code } = req.body;
    
    if (!email || !code) {
      return res.status(400).json({ message: 'Vui lòng cung cấp email và mã xác nhận' });
    }
    
    const resetData = resetCodes.get(email);
    
    if (!resetData) {
      return res.status(400).json({ message: 'Mã xác nhận không hợp lệ hoặc đã hết hạn' });
    }
    
    if (resetData.expiresAt < Date.now()) {
      resetCodes.delete(email);
      return res.status(400).json({ message: 'Mã xác nhận đã hết hạn' });
    }
    
    if (resetData.code !== code) {
      return res.status(400).json({ message: 'Mã xác nhận không đúng' });
    }
    
    // Mã hợp lệ
    res.json({ message: 'Mã xác nhận hợp lệ' });
  } catch (error) {
    console.error('Verify code error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Reset password endpoint
app.post('/api/reset-password', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Vui lòng cung cấp email và mật khẩu mới' });
    }
    
    // Kiểm tra xem email có mã reset hợp lệ không
    const resetData = resetCodes.get(email);
    if (!resetData) {
      return res.status(400).json({ message: 'Vui lòng yêu cầu mã xác nhận trước' });
    }
    
    // Xóa mã reset đã sử dụng
    resetCodes.delete(email);
    
    // Mã hóa mật khẩu mới
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Cập nhật mật khẩu trong database
    if (mongoose.connection.readyState === 1) {
      const result = await User.updateOne(
        { email },
        { $set: { password: hashedPassword } }
      );
      
      if (result.modifiedCount === 0) {
        return res.status(404).json({ message: 'Không tìm thấy người dùng' });
      }
    } else {
      const userIndex = users.findIndex(u => u.email === email);
      if (userIndex !== -1) {
        users[userIndex].password = hashedPassword;
      } else {
        return res.status(404).json({ message: 'Không tìm thấy người dùng' });
      }
    }
    
    res.json({ message: 'Đặt lại mật khẩu thành công' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get all users endpoint
app.get('/api/users', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    if (mongoose.connection.readyState === 1) {
      const users = await User.find({}, { password: 0 });
      res.json(users);
    } else {
      // Trả về dữ liệu giả nếu không kết nối được MongoDB
      const mockUsers = [
        { id: 1, username: 'Anh', age: 25, gender: 'female', income: '10-20', location: 'hanoi', isVip: true },
        { id: 2, username: 'Bình', age: 28, gender: 'male', income: '20-30', location: 'hcm', isVip: false },
        { id: 3, username: 'Chi', age: 23, gender: 'female', income: '5-10', location: 'danang', isVip: false },
        { id: 4, username: 'Dũng', age: 30, gender: 'male', income: '30+', location: 'hanoi', isVip: true },
        { id: 5, username: 'Giang', age: 26, gender: 'female', income: '10-20', location: 'hcm', isVip: false },
        { id: 6, username: 'Huy', age: 32, gender: 'male', income: '20-30', location: 'danang', isVip: true },
        { id: 7, username: 'Linh', age: 24, gender: 'female', income: '5-10', location: 'hanoi', isVip: false },
        { id: 8, username: 'Minh', age: 29, gender: 'male', income: '30+', location: 'hcm', isVip: true }
      ];
      res.json(mockUsers);
    }
  } catch (error) {
    console.error('Get users error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get user by ID endpoint
app.get('/api/user/:id', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const userId = req.params.id;
    
    if (mongoose.connection.readyState === 1) {
      const user = await User.findById(userId, { password: 0 });
      if (!user) {
        return res.status(404).json({ message: 'Không tìm thấy người dùng' });
      }
      
      // Get additional stats
      const friendsCount = user.friends ? user.friends.length : 0;
      const matchesCount = user.matches ? user.matches.length : 0;
      const postsCount = await Post.countDocuments({ userId: user._id });
      
      res.json({
        ...user.toObject(),
        friendsCount,
        matchesCount,
        postsCount
      });
    } else {
      // Trả về dữ liệu giả nếu không kết nối được MongoDB
      const mockUser = {
        id: userId,
        username: 'Người dùng ' + userId,
        email: `user${userId}@example.com`,
        profile: {
          age: Math.floor(Math.random() * 15) + 20,
          gender: ['male', 'female'][Math.floor(Math.random() * 2)],
          bio: 'Rất vui được làm quen!',
          interests: ['Du lịch', 'Âm nhạc', 'Thể thao'],
          location: ['hanoi', 'hcm', 'danang'][Math.floor(Math.random() * 3)],
          income: ['0-5', '5-10', '10-20', '20-30', '30+'][Math.floor(Math.random() * 5)]
        },
        isVip: Math.random() > 0.5,
        friendsCount: Math.floor(Math.random() * 50),
        matchesCount: Math.floor(Math.random() * 20),
        postsCount: Math.floor(Math.random() * 10)
      };
      res.json(mockUser);
    }
  } catch (error) {
    console.error('Get user error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Update user profile endpoint
app.put('/api/user/:id', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const userId = req.params.id;
    const updateData = req.body;
    
    // Check authentication
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Token không hợp lệ' });
    }
    
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key');
    
    if (decoded.userId !== userId && !decoded.isAdmin) {
      return res.status(403).json({ message: 'Không có quyền cập nhật thông tin người dùng này' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const user = await User.findByIdAndUpdate(
        userId,
        { $set: updateData },
        { new: true, select: { password: 0 } }
      );
      
      if (!user) {
        return res.status(404).json({ message: 'Không tìm thấy người dùng' });
      }
      
      res.json({ message: 'Cập nhật thông tin thành công', user });
    } else {
      // Fallback mode
      const userIndex = users.findIndex(u => u.id == userId);
      if (userIndex === -1) {
        return res.status(404).json({ message: 'Không tìm thấy người dùng' });
      }
      
      users[userIndex] = { ...users[userIndex], ...updateData };
      res.json({ message: 'Cập nhật thông tin thành công (fallback mode)', user: users[userIndex] });
    }
  } catch (error) {
    console.error('Update user error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get user friends endpoint
app.get('/api/user/:id/friends', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const userId = req.params.id;
    
    if (mongoose.connection.readyState === 1) {
      const user = await User.findById(userId).populate('friends', 'username profile avatar');
      if (!user) {
        return res.status(404).json({ message: 'Không tìm thấy người dùng' });
      }
      res.json(user.friends);
    } else {
      // Trả về dữ liệu giả nếu không kết nối được MongoDB
      const mockFriends = [
        { id: 1, username: 'Anh', profile: { avatar: null } },
        { id: 2, username: 'Bình', profile: { avatar: null } },
        { id: 3, username: 'Chi', profile: { avatar: null } },
        { id: 4, username: 'Dũng', profile: { avatar: null } },
        { id: 5, username: 'Giang', profile: { avatar: null } }
      ];
      res.json(mockFriends);
    }
  } catch (error) {
    console.error('Get friends error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get matching users endpoint
app.get('/api/matching-users', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    if (mongoose.connection.readyState === 1) {
      const users = await User.find({}, { password: 0 }).limit(8);
      res.json(users);
    } else {
      // Trả về dữ liệu giả nếu không kết nối được MongoDB
      const mockUsers = [
        { id: 1, username: 'Anh', age: 25, gender: 'female', income: '10-20', location: 'hanoi', bio: 'Yêu thích du lịch và ẩm thực' },
        { id: 2, username: 'Bình', age: 28, gender: 'male', income: '20-30', location: 'hcm', bio: 'Đam mê thể thao và âm nhạc' },
        { id: 3, username: 'Chi', age: 23, gender: 'female', income: '5-10', location: 'danang', bio: 'Thích đọc sách và xem phim' },
        { id: 4, username: 'Dũng', age: 30, gender: 'male', income: '30+', location: 'hanoi', bio: 'Công nghệ và đầu tư là đam mê' },
        { id: 5, username: 'Giang', age: 26, gender: 'female', income: '10-20', location: 'hcm', bio: 'Yêu động vật và thiên nhiên' },
        { id: 6, username: 'Huy', age: 32, gender: 'male', income: '20-30', location: 'danang', bio: 'Thích nấu ăn và khám phá' },
        { id: 7, username: 'Linh', age: 24, gender: 'female', income: '5-10', location: 'hanoi', bio: 'Đam mê thời trang và làm đẹp' },
        { id: 8, username: 'Minh', age: 29, gender: 'male', income: '30+', location: 'hcm', bio: 'Yêu xe hơi và công nghệ' }
      ];
      res.json(mockUsers);
    }
  } catch (error) {
    console.error('Get matching users error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get posts endpoint
app.get('/api/posts', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { userId, page = 1, limit = 10 } = req.query;
    
    if (mongoose.connection.readyState === 1) {
      let query = {};
      if (userId) {
        query.userId = userId;
      }
      
      const posts = await Post.find(query)
        .populate('userId', 'username profile')
        .sort({ createdAt: -1 })
        .limit(limit * 1)
        .skip((page - 1) * limit);
      
      res.json(posts);
    } else {
      // Trả về dữ liệu giả nếu không kết nối được MongoDB
      const mockPosts = [
        {
          id: 1,
          userId: { id: 2, username: 'Bình', profile: { avatar: null } },
          content: 'Hôm nay thời tiết thật đẹp, ai rảnh đi cà phê không?',
          createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
          likes: 15,
          comments: 5
        },
        {
          id: 2,
          userId: { id: 4, username: 'Dũng', profile: { avatar: null } },
          content: 'Vừa hoàn thành xong dự án mới, cảm thấy thật hạnh phúc!',
          image: 'https://picsum.photos/600/400?random=1',
          createdAt: new Date(Date.now() - 5 * 60 * 60 * 1000),
          likes: 32,
          comments: 8
        },
        {
          id: 3,
          userId: { id: 1, username: 'Anh', profile: { avatar: null } },
          content: 'Chia sẻ khoảnh khắc đáng yêu của mình tại bãi biển Nha Trang 😍',
          image: 'https://picsum.photos/600/400?random=2',
          createdAt: new Date(Date.now() - 24 * 60 * 60 * 1000),
          likes: 78,
          comments: 12
        }
      ];
      res.json(mockPosts);
    }
  } catch (error) {
    console.error('Get posts error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Create post endpoint
app.post('/api/posts', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { userId, content, image, video } = req.body;
    
    if (!userId) {
      return res.status(400).json({ message: 'Thiếu thông tin userId' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const newPost = new Post({
        userId,
        content,
        image,
        video
      });
      
      await newPost.save();
      await newPost.populate('userId', 'username profile');
      
      res.status(201).json({ message: 'Đăng bài thành công', post: newPost });
    } else {
      // Fallback mode
      const newPost = {
        id: nextId++,
        userId: { id: userId, username: 'User' + userId, profile: { avatar: null } },
        content,
        image,
        video,
        likes: 0,
        comments: [],
        createdAt: new Date()
      };
      
      res.status(201).json({ message: 'Đăng bài thành công (fallback mode)', post: newPost });
    }
  } catch (error) {
    console.error('Create post error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get messages between users endpoint
app.get('/api/messages', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { userId, friendId } = req.query;
    
    if (!userId || !friendId) {
      return res.status(400).json({ message: 'Thiếu thông tin userId hoặc friendId' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const messages = await Message.find({
        $or: [
          { sender: userId, receiver: friendId },
          { sender: friendId, receiver: userId }
        ]
      })
      .populate('sender', 'username profile')
      .populate('receiver', 'username profile')
      .sort({ createdAt: 1 });
      
      res.json(messages);
    } else {
      // Trả về dữ liệu giả nếu không kết nối được MongoDB
      const mockMessages = [
        {
          id: 1,
          sender: { id: friendId, username: 'User' + friendId, profile: { avatar: null } },
          receiver: { id: userId, username: 'User' + userId, profile: { avatar: null } },
          content: 'Xin chào! Bạn có khỏe không?',
          createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000)
        },
        {
          id: 2,
          sender: { id: userId, username: 'User' + userId, profile: { avatar: null } },
          receiver: { id: friendId, username: 'User' + friendId, profile: { avatar: null } },
          content: 'Mình khỏe, cảm ơn bạn! Còn bạn?',
          createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000 + 60000)
        },
        {
          id: 3,
          sender: { id: friendId, username: 'User' + friendId, profile: { avatar: null } },
          receiver: { id: userId, username: 'User' + userId, profile: { avatar: null } },
          content: 'Mình cũng khỏe. Bạn đang làm gì vậy?',
          createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000 + 120000)
        }
      ];
      res.json(mockMessages);
    }
  } catch (error) {
    console.error('Get messages error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Send message endpoint
app.post('/api/messages', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { sender, receiver, content } = req.body;
    
    if (!sender || !receiver || !content) {
      return res.status(400).json({ message: 'Thiếu thông tin sender, receiver hoặc content' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const newMessage = new Message({
        sender,
        receiver,
        content
      });
      
      await newMessage.save();
      await newMessage.populate('sender', 'username profile');
      await newMessage.populate('receiver', 'username profile');
      
      // Send notification via WebSocket
      sendNotification(receiver, {
        type: 'message',
        content: `Bạn có tin nhắn mới từ ${newMessage.sender.username}`,
        relatedId: sender
      });
      
      res.status(201).json({ message: 'Gửi tin nhắn thành công', message: newMessage });
    } else {
      // Fallback mode
      const newMessage = {
        id: nextId++,
        sender: { id: sender, username: 'User' + sender, profile: { avatar: null } },
        receiver: { id: receiver, username: 'User' + receiver, profile: { avatar: null } },
        content,
        createdAt: new Date()
      };
      
      res.status(201).json({ message: 'Gửi tin nhắn thành công (fallback mode)', message: newMessage });
    }
  } catch (error) {
    console.error('Send message error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Add friend endpoint
app.post('/api/friends', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { userId, friendId } = req.body;
    
    if (!userId || !friendId) {
      return res.status(400).json({ message: 'Thiếu thông tin userId hoặc friendId' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const user = await User.findById(userId);
      const friend = await User.findById(friendId);
      
      if (!user || !friend) {
        return res.status(404).json({ message: 'Không tìm thấy người dùng' });
      }
      
      // Check if already friends
      if (user.friends.includes(friendId)) {
        return res.status(400).json({ message: 'Đã là bạn bè' });
      }
      
      // Add to friends list
      user.friends.push(friendId);
      friend.friends.push(userId);
      
      await user.save();
      await friend.save();
      
      // Send notification
      sendNotification(friendId, {
        type: 'friend_request',
        content: `${user.username} đã gửi lời mời kết bạn`,
        relatedId: userId
      });
      
      res.json({ message: 'Kết bạn thành công' });
    } else {
      // Fallback mode
      res.json({ message: 'Kết bạn thành công (fallback mode)' });
    }
  } catch (error) {
    console.error('Add friend error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get notifications endpoint
app.get('/api/notifications', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { userId } = req.query;
    
    if (!userId) {
      return res.status(400).json({ message: 'Thiếu thông tin userId' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const notifications = await Notification.find({ userId })
        .sort({ createdAt: -1 })
        .limit(20);
      
      res.json(notifications);
    } else {
      // Trả về dữ liệu giả nếu không kết nối được MongoDB
      const mockNotifications = [
        {
          id: 1,
          type: 'friend_request',
          content: 'Anh đã gửi lời mời kết bạn',
          isRead: false,
          createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000)
        },
        {
          id: 2,
          type: 'message',
          content: 'Bình đã gửi cho bạn một tin nhắn',
          isRead: true,
          createdAt: new Date(Date.now() - 5 * 60 * 60 * 1000)
        },
        {
          id: 3,
          type: 'admin',
          content: 'Tài khoản VIP của bạn đã được kích hoạt',
          isRead: false,
          createdAt: new Date(Date.now() - 24 * 60 * 60 * 1000)
        }
      ];
      res.json(mockNotifications);
    }
  } catch (error) {
    console.error('Get notifications error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Create VIP request endpoint
app.post('/api/vip-request', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { userId, planType, amount, paymentProof } = req.body;
    
    if (!userId || !planType || !amount) {
      return res.status(400).json({ message: 'Thiếu thông tin userId, planType hoặc amount' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const vipRequest = new VIPRequest({
        userId,
        planType,
        amount,
        paymentProof
      });
      
      await vipRequest.save();
      
      // Send email to admin
      const user = await User.findById(userId);
      const mailOptions = {
        from: process.env.EMAIL_USER || 'mailcheckctv@gmail.com',
        to: 'mailcheckctv@gmail.com',
        subject: 'Yêu cầu nâng cấp VIP mới - LoveConnect',
        html: `
          <h2>Yêu cầu nâng cấp VIP mới</h2>
          <p><strong>Người dùng:</strong> ${user.username} (${user.email})</p>
          <p><strong>Gói:</strong> ${planType}</p>
          <p><strong>Số tiền:</strong> ${amount.toLocaleString('vi-VN')} VNĐ</p>
          ${paymentProof ? `<p><strong>Ảnh chứng minh:</strong> <a href="${paymentProof}">Xem ảnh</a></p>` : ''}
          <p>Vui lòng kiểm tra và xác nhận yêu cầu này trong trang quản trị.</p>
        `
      };
      
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
        } else {
          console.log('Email sent:', info.response);
        }
      });
      
      res.status(201).json({ message: 'Gửi yêu cầu nâng cấp VIP thành công' });
    } else {
      // Fallback mode
      res.status(201).json({ message: 'Gửi yêu cầu nâng cấp VIP thành công (fallback mode)' });
    }
  } catch (error) {
    console.error('VIP request error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get VIP requests endpoint (admin only)
app.get('/api/vip-requests', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    // Check admin authentication
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Token không hợp lệ' });
    }
    
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key');
    
    if (!decoded.isAdmin) {
      return res.status(403).json({ message: 'Chỉ admin mới có quyền truy cập' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const requests = await VIPRequest.find()
        .populate('userId', 'username email')
        .sort({ createdAt: -1 });
      
      res.json(requests);
    } else {
      // Fallback mode
      const mockRequests = [
        {
          id: 1,
          userId: { id: 1, username: 'user1', email: 'user1@example.com' },
          planType: 'premium',
          amount: 499000,
          status: 'pending',
          createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000)
        },
        {
          id: 2,
          userId: { id: 2, username: 'user2', email: 'user2@example.com' },
          planType: 'basic',
          amount: 199000,
          status: 'approved',
          createdAt: new Date(Date.now() - 5 * 60 * 60 * 1000)
        }
      ];
      res.json(mockRequests);
    }
  } catch (error) {
    console.error('Get VIP requests error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Update VIP request status endpoint (admin only)
app.put('/api/vip-request/:id', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const requestId = req.params.id;
    const { status } = req.body;
    
    // Check admin authentication
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Token không hợp lệ' });
    }
    
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key');
    
    if (!decoded.isAdmin) {
      return res.status(403).json({ message: 'Chỉ admin mới có quyền thực hiện' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const vipRequest = await VIPRequest.findById(requestId).populate('userId');
      
      if (!vipRequest) {
        return res.status(404).json({ message: 'Không tìm thấy yêu cầu' });
      }
      
      vipRequest.status = status;
      await vipRequest.save();
      
      if (status === 'approved') {
        // Update user VIP status
        const user = await User.findById(vipRequest.userId._id);
        user.isVip = true;
        user.vipType = vipRequest.planType;
        
        // Set expiry date based on plan type
        const expiryDate = new Date();
        if (vipRequest.planType === 'week') {
          expiryDate.setDate(expiryDate.getDate() + 7);
        } else if (vipRequest.planType === 'basic') {
          expiryDate.setMonth(expiryDate.getMonth() + 1);
        } else if (vipRequest.planType === 'premium') {
          expiryDate.setMonth(expiryDate.getMonth() + 1);
        }
        
        user.vipExpiry = expiryDate;
        await user.save();
        
        // Send notification to user
        sendNotification(user._id.toString(), {
          type: 'vip_approved',
          content: `Tài khoản VIP ${vipRequest.planType} của bạn đã được kích hoạt`,
          relatedId: user._id
        });
      }
      
      res.json({ message: 'Cập nhật trạng thái yêu cầu thành công' });
    } else {
      // Fallback mode
      res.json({ message: 'Cập nhật trạng thái yêu cầu thành công (fallback mode)' });
    }
  } catch (error) {
    console.error('Update VIP request error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Send support message endpoint
app.post('/api/support', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { userId, message } = req.body;
    
    if (!userId || !message) {
      return res.status(400).json({ message: 'Thiếu thông tin userId hoặc message' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const user = await User.findById(userId);
      
      if (!user) {
        return res.status(404).json({ message: 'Không tìm thấy người dùng' });
      }
      
      // Send email to support
      const mailOptions = {
        from: process.env.EMAIL_USER || 'mailcheckctv@gmail.com',
        to: 'mailcheckctv@gmail.com',
        subject: 'Tin nhắn hỗ trợ mới - LoveConnect',
        html: `
          <h2>Tin nhắn hỗ trợ mới</h2>
          <p><strong>Người dùng:</strong> ${user.username} (${user.email})</p>
          <p><strong>Nội dung:</strong></p>
          <p>${message}</p>
          <p>Vui lòng phản hồi tin nhắn này trong thời gian sớm nhất.</p>
        `
      };
      
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
        } else {
          console.log('Email sent:', info.response);
        }
      });
      
      res.json({ message: 'Gửi tin nhắn hỗ trợ thành công' });
    } else {
      // Fallback mode
      res.json({ message: 'Gửi tin nhắn hỗ trợ thành công (fallback mode)' });
    }
  } catch (error) {
    console.error('Support message error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Upload image endpoint
app.post('/api/upload', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { image, type = 'avatar' } = req.body;
    
    if (!image) {
      return res.status(400).json({ message: 'Không có dữ liệu ảnh' });
    }
    
    // In a real application, you would upload to cloud storage like AWS S3, Cloudinary, etc.
    // For this demo, we'll just return a mock URL
    const imageUrl = `https://api.dicebear.com/7.x/avataaars/svg?seed=${Date.now()}`;
    
    res.json({ url: imageUrl, message: 'Tải ảnh lên thành công' });
  } catch (error) {
    console.error('Upload image error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// ==================== STATIC ROUTES - FIX QUAN TRỌNG ====================
// Route cho trang chính
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Route cho các trang cụ thể
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dang-ky', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dang-ky.html'));
});

app.get('/trang-chu', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'trang-chu.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Route cho tất cả các requests khác - serve file tĩnh
app.get('*', (req, res) => {
  // Ưu tiên trả về trang đăng nhập cho route gốc
  if (req.path === '/' || req.path === '') {
    return res.sendFile(path.join(__dirname, 'public', 'login.html'));
  }
  
  const filePath = path.join(__dirname, 'public', req.path);
  
  // Kiểm tra nếu file tồn tại
  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (err) {
      // Nếu file không tồn tại, trả về login.html
      res.sendFile(path.join(__dirname, 'public', 'login.html'));
    } else {
      // Nếu file tồn tại, serve file đó
      res.sendFile(filePath);
    }
  });
});

// ==================== ERROR HANDLING ====================
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.status(500).json({ message: 'Lỗi server không xác định', error: err.message });
});

// ==================== START SERVER ====================
server.listen(PORT, HOST, () => {
  console.log(`=== SERVER DATING APP ===`);
  console.log(`🚀 Server đang chạy trên ${HOST}:${PORT}`);
  console.log(`🌍 Môi trường: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Kết nối MongoDB: ${mongoose.connection.readyState === 1 ? '✅ Thành công' : '❌ Thất bại'}`);
  console.log(`📁 Phục vụ file tĩnh từ: ${path.join(__dirname, 'public')}`);
  console.log(`🔌 WebSocket server đang chạy`);
  console.log(`================================`);
});