require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
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

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// SERVING STATIC FILES - FIX QUAN TRỌNG
app.use(express.static(path.join(__dirname, 'public'), {
  index: 'login.html', // Mặc định là login.html
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
    avatar: String
  },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// ==================== FALLBACK DATA ====================
let users = [];
let nextId = 1;

// ==================== RESET PASSWORD HANDLING ====================
const resetCodes = new Map();

function generateResetCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function sendResetCode(email, code) {
  console.log(`Mã xác nhận cho ${email}: ${code}`);
  // Trong thực tế, bạn sẽ tích hợp service gửi email ở đây
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
        friends: []
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
          profile: newUser.profile
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
        profile: user.profile
      },
      message: 'Đăng nhập thành công'
    });
  } catch (error) {
    console.error('Login error:', error);
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
    
    // Gửi mã (mô phỏng)
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
        return res.status(404).json({ message: 'Không tìm thấy người dùng' );
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
      res.json(user);
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
          interests: ['Du lịch', 'Âm nhạc', 'Thể thao']
        },
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

// Get user friends endpoint
app.get('/api/user/:id/friends', async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const userId = req.params.id;
    
    if (mongoose.connection.readyState === 1) {
      const user = await User.findById(userId).populate('friends', 'username profileImage');
      if (!user) {
        return res.status(404).json({ message: 'Không tìm thấy người dùng' });
      }
      res.json(user.friends);
    } else {
      // Trả về dữ liệu giả nếu không kết nối được MongoDB
      const mockFriends = [
        { id: 1, username: 'Anh', profileImage: null },
        { id: 2, username: 'Bình', profileImage: null },
        { id: 3, username: 'Chi', profileImage: null },
        { id: 4, username: 'Dũng', profileImage: null },
        { id: 5, username: 'Giang', profileImage: null }
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
app.listen(PORT, HOST, () => {
  console.log(`=== SERVER DATING APP ===`);
  console.log(`🚀 Server đang chạy trên ${HOST}:${PORT}`);
  console.log(`🌍 Môi trường: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Kết nối MongoDB: ${mongoose.connection.readyState === 1 ? '✅ Thành công' : '❌ Thất bại'}`);
  console.log(`📁 Phục vụ file tĩnh từ: ${path.join(__dirname, 'public')}`);
  console.log(`================================`);
});