require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
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
    location: String,
    income: String,
    interests: [String],
    avatar: String
  },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  matches: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  isVip: { type: Boolean, default: false },
  vipExpiration: Date,
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
  content: String,
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const Message = mongoose.model('Message', MessageSchema);

// ==================== WEBSOCKET FOR REAL-TIME COMMUNICATION ====================
const activeUsers = new Map();

wss.on('connection', (ws, req) => {
  console.log('🔗 New WebSocket connection');
  
  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data);
      
      switch (message.type) {
        case 'auth':
          // Lưu thông tin user với WebSocket connection
          activeUsers.set(message.userId, ws);
          ws.userId = message.userId;
          console.log(`User ${message.userId} authenticated via WebSocket`);
          break;
          
        case 'message':
          // Xử lý tin nhắn real-time
          handleRealTimeMessage(message, ws);
          break;
          
        case 'typing':
          // Xử lý thông báo đang nhập
          handleTypingIndicator(message, ws);
          break;
          
        case 'online':
          // Cập nhật trạng thái online
          broadcastOnlineStatus(message.userId, true);
          break;
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  });
  
  ws.on('close', () => {
    if (ws.userId) {
      activeUsers.delete(ws.userId);
      broadcastOnlineStatus(ws.userId, false);
      console.log(`User ${ws.userId} disconnected from WebSocket`);
    }
  });
});

function handleRealTimeMessage(message, ws) {
  // Lưu tin nhắn vào database
  const newMessage = new Message({
    sender: message.senderId,
    receiver: message.receiverId,
    content: message.content
  });
  
  newMessage.save()
    .then(savedMessage => {
      // Gửi tin nhắn đến người nhận nếu online
      const receiverWs = activeUsers.get(message.receiverId);
      if (receiverWs) {
        receiverWs.send(JSON.stringify({
          type: 'message',
          message: {
            id: savedMessage._id,
            sender: message.senderId,
            content: message.content,
            createdAt: savedMessage.createdAt
          }
        }));
      }
      
      // Xác nhận cho người gửi
      ws.send(JSON.stringify({
        type: 'message_sent',
        messageId: savedMessage._id
      }));
    })
    .catch(error => {
      console.error('Error saving message:', error);
    });
}

function handleTypingIndicator(message, ws) {
  const receiverWs = activeUsers.get(message.receiverId);
  if (receiverWs) {
    receiverWs.send(JSON.stringify({
      type: 'typing',
      senderId: message.senderId,
      isTyping: message.isTyping
    }));
  }
}

function broadcastOnlineStatus(userId, isOnline) {
  // Gửi thông báo trạng thái online đến tất cả bạn bè
  User.findById(userId)
    .then(user => {
      if (user && user.friends.length > 0) {
        user.friends.forEach(friendId => {
          const friendWs = activeUsers.get(friendId.toString());
          if (friendWs) {
            friendWs.send(JSON.stringify({
              type: 'online_status',
              userId: userId,
              isOnline: isOnline
            }));
          }
        });
      }
    })
    .catch(error => {
      console.error('Error broadcasting online status:', error);
    });
}

// ==================== AUTHENTICATION MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ message: 'Token truy cập không tồn tại' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Token không hợp lệ' });
    }
    req.user = user;
    next();
  });
};

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
          profile: newUser.profile
        }
      });
    } else {
      res.status(500).json({ message: 'Không thể kết nối đến database' });
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
    }
    
    if (!user) {
      return res.status(400).json({ message: 'Tên đăng nhập hoặc mật khẩu không đúng' });
    }
    
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET || 'fallback_secret_key', 
      { expiresIn: '24h' }
    );
    
    res.json({ 
      token, 
      user: { 
        id: user._id, 
        username: user.username,
        email: user.email,
        profile: user.profile,
        isVip: user.isVip,
        friends: user.friends,
        matches: user.matches
      },
      message: 'Đăng nhập thành công'
    });
  } catch (error) {
    console.error('Login error:', error);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get current user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .populate('friends', 'username profile')
      .populate('matches', 'username profile');
    
    if (!user) {
      return res.status(404).json({ message: 'Người dùng không tồn tại' });
    }
    
    res.json({
      id: user._id,
      username: user.username,
      email: user.email,
      profile: user.profile,
      isVip: user.isVip,
      friends: user.friends,
      matches: user.matches,
      createdAt: user.createdAt
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Update user profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { profile } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { $set: { profile } },
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({ message: 'Người dùng không tồn tại' });
    }
    
    res.json({
      message: 'Cập nhật thông tin thành công',
      profile: user.profile
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get suggested users
app.get('/api/users/suggested', authenticateToken, async (req, res) => {
  try {
    const currentUser = await User.findById(req.user.userId);
    
    // Lấy người dùng không phải là bạn bè và không phải là chính mình
    const suggestedUsers = await User.find({
      _id: { 
        $ne: currentUser._id, 
        $nin: currentUser.friends 
      }
    })
    .limit(10)
    .select('username profile');
    
    res.json(suggestedUsers);
  } catch (error) {
    console.error('Suggested users error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get user by ID
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('username profile isVip');
    
    if (!user) {
      return res.status(404).json({ message: 'Người dùng không tồn tại' });
    }
    
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Add friend
app.post('/api/friends/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Kiểm tra xem người dùng có tồn tại không
    const userToAdd = await User.findById(userId);
    if (!userToAdd) {
      return res.status(404).json({ message: 'Người dùng không tồn tại' });
    }
    
    // Thêm vào danh sách bạn bè
    await User.findByIdAndUpdate(
      req.user.userId,
      { $addToSet: { friends: userId } }
    );
    
    res.json({ message: 'Đã thêm bạn thành công' });
  } catch (error) {
    console.error('Add friend error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get friends list
app.get('/api/friends', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .populate('friends', 'username profile');
    
    if (!user) {
      return res.status(404).json({ message: 'Người dùng không tồn tại' });
    }
    
    res.json(user.friends);
  } catch (error) {
    console.error('Get friends error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Like a user (match)
app.post('/api/like/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Kiểm tra xem người dùng có tồn tại không
    const userToLike = await User.findById(userId);
    if (!userToLike) {
      return res.status(404).json({ message: 'Người dùng không tồn tại' });
    }
    
    // Thêm vào danh sách matches
    await User.findByIdAndUpdate(
      req.user.userId,
      { $addToSet: { matches: userId } }
    );
    
    // Kiểm tra xem có match không (nếu người kia cũng like mình)
    const isMatch = userToLike.matches.includes(req.user.userId);
    
    res.json({ 
      message: 'Đã thích thành công',
      isMatch: isMatch
    });
  } catch (error) {
    console.error('Like user error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get posts
app.get('/api/posts', authenticateToken, async (req, res) => {
  try {
    const posts = await Post.find()
      .populate('userId', 'username profile')
      .sort({ createdAt: -1 })
      .limit(20);
    
    res.json(posts);
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Create post
app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { content, image, video } = req.body;
    
    const newPost = new Post({
      userId: req.user.userId,
      content,
      image,
      video,
      likes: [],
      comments: []
    });
    
    await newPost.save();
    
    // Populate user info before sending response
    await newPost.populate('userId', 'username profile');
    
    res.status(201).json({
      message: 'Đăng bài thành công',
      post: newPost
    });
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Like a post
app.post('/api/posts/:postId/like', authenticateToken, async (req, res) => {
  try {
    const { postId } = req.params;
    
    const post = await Post.findByIdAndUpdate(
      postId,
      { $addToSet: { likes: req.user.userId } },
      { new: true }
    );
    
    if (!post) {
      return res.status(404).json({ message: 'Bài viết không tồn tại' });
    }
    
    res.json({ message: 'Đã thích bài viết' });
  } catch (error) {
    console.error('Like post error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Get messages between users
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const messages = await Message.find({
      $or: [
        { sender: req.user.userId, receiver: userId },
        { sender: userId, receiver: req.user.userId }
      ]
    })
    .populate('sender', 'username profile')
    .populate('receiver', 'username profile')
    .sort({ createdAt: 1 });
    
    res.json(messages);
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Send message
app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { receiverId, content } = req.body;
    
    const newMessage = new Message({
      sender: req.user.userId,
      receiver: receiverId,
      content
    });
    
    await newMessage.save();
    
    // Populate sender info before sending response
    await newMessage.populate('sender', 'username profile');
    
    res.status(201).json({
      message: 'Tin nhắn đã được gửi',
      message: newMessage
    });
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Upgrade to VIP
app.post('/api/upgrade-vip', authenticateToken, async (req, res) => {
  try {
    const { plan } = req.body;
    
    let expirationDate = new Date();
    
    switch (plan) {
      case 'week':
        expirationDate.setDate(expirationDate.getDate() + 7);
        break;
      case 'basic':
      case 'premium':
        expirationDate.setMonth(expirationDate.getMonth() + 1);
        break;
      default:
        return res.status(400).json({ message: 'Gói không hợp lệ' });
    }
    
    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { 
        isVip: true,
        vipExpiration: expirationDate
      },
      { new: true }
    );
    
    res.json({
      message: 'Nâng cấp VIP thành công',
      isVip: user.isVip,
      vipExpiration: user.vipExpiration
    });
  } catch (error) {
    console.error('Upgrade VIP error:', error);
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
  console.log(`🔗 WebSocket server ready for connections`);
  console.log(`================================`);
});