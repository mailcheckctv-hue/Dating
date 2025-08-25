require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 1000;

// Kết nối MongoDB ĐƠN GIẢN
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://datingappuser:Check68%40@cluster0.hsl2eh4.mongodb.net/dating-app?retryWrites=true&w=majority';

console.log('🔄 Đang kết nối đến MongoDB...');
console.log('📝 URI:', MONGODB_URI.replace(/:[^:]*@/, ':****@'));

// Kết nối MongoDB trực tiếp - XÓA HÀM connectDB() VÀ CHỈ DÙNG CODE NÀY
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('✅ Kết nối MongoDB thành công!');
  })
  .catch((error) => {
    console.log('❌ Lỗi kết nối MongoDB, sử dụng fallback mode...');
    console.log('💡 Lỗi:', error.message);
  });

// Middleware - CORS configuration chi tiết
app.use(cors({
  origin: function(origin, callback) {
    callback(null, true);
  },
  credentials: true,
  optionsSuccessStatus: 200
}));

// ... (phần middleware và các route tiếp theo giữ nguyên) ...

// Thêm middleware để xử lý preflight requests
app.options('*', cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Phục vụ file tĩnh từ thư mục public
app.use(express.static(path.join(__dirname, 'public')));
// Middleware logging để debug
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});
// Test endpoint - kiểm tra server có hoạt động
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Server is working!',
    timestamp: new Date().toISOString(),
    port: PORT
  });
});

// Kết nối MongoDB với timeout dài hơn và xử lý lỗi chi tiết

console.log('🔄 Đang kết nối đến MongoDB...');
console.log('📝 URI:', MONGODB_URI);

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 10000, // Tăng timeout lên 10 giây
  socketTimeoutMS: 45000,
})
.then(() => {
  console.log('✅ Đã kết nối đến MongoDB thành công!');
  console.log('📊 Database:', mongoose.connection.name);
})
.catch(err => {
  console.error('❌ Lỗi kết nối MongoDB:', err.message);
  console.log('🔄 Sử dụng dữ liệu tạm thời (fallback mode)...');
  console.log('💡 Hướng dẫn khắc phục:');
  console.log('1. Kiểm tra MongoDB đã được cài đặt và chạy chưa');
  console.log('2. Chạy lệnh "mongod" trong Command Prompt/Terminal');
  console.log('3. Kiểm tra file .env có MONGODB_URI không');
});

// Xử lý sự kiện kết nối MongoDB
mongoose.connection.on('connected', () => {
  console.log('✅ Kết nối MongoDB thành công');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ Lỗi kết nối MongoDB:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB đã ngắt kết nối');
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

// Dữ liệu tạm thời (sử dụng khi không kết nối được MongoDB)
let users = [];
let posts = [];
let messages = [];
let nextId = 1;
let nextPostId = 1;
let nextMessageId = 1;

// Tạo user test mặc định trong fallback mode
if (mongoose.connection.readyState !== 1 && users.length === 0) {
  console.log('👤 Tạo tài khoản test trong fallback mode...');
  
  // Tạo password đã mã hóa cho user test
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

// Debug endpoint - kiểm tra chi tiết database
app.get('/api/debug/db', async (req, res) => {
  try {
    const dbStatus = {
      status: 'OK',
      timestamp: new Date().toISOString(),
      mongooseState: mongoose.STATES[mongoose.connection.readyState],
      mongooseReadyState: mongoose.connection.readyState,
      usingFallback: mongoose.connection.readyState !== 1,
      environment: process.env.NODE_ENV || 'development',
      hasMongoUri: !!process.env.MONGODB_URI,
      mongoUriPresent: !!process.env.MONGODB_URI,
      appName: 'Dating App'
    };

    if (mongoose.connection.readyState === 1) {
      // Nếu kết nối MongoDB thành công
      try {
        const userCount = await User.countDocuments();
        const postCount = await Post.countDocuments();
        dbStatus.userCount = userCount;
        dbStatus.postCount = postCount;
        dbStatus.dbStats = 'Connected and operational';
        
        // Kiểm tra collections
        const collections = await mongoose.connection.db.listCollections().toArray();
        dbStatus.collections = collections.map(col => col.name);
        
      } catch (dbError) {
        dbStatus.dbError = dbError.message;
      }
    } else {
      // Chế độ fallback
      dbStatus.fallbackUserCount = users.length;
      dbStatus.fallbackPostCount = posts.length;
      dbStatus.dbStats = 'Using fallback data';
    }

    res.json(dbStatus);
  } catch (error) {
    res.status(500).json({ 
      error: error.message,
      mongooseState: mongoose.STATES[mongoose.connection.readyState],
      timestamp: new Date().toISOString()
    });
  }
});

// Endpoint kiểm tra chi tiết kết nối database
app.get('/api/debug/db-connection', (req, res) => {
  const connectionStates = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting',
    99: 'uninitialized'
  };
  
  res.json({
    mongooseState: connectionStates[mongoose.connection.readyState],
    readyState: mongoose.connection.readyState,
    mongoUri: process.env.MONGODB_URI ? '***' : 'not set',
    usingFallback: mongoose.connection.readyState !== 1,
    timestamp: new Date().toISOString()
  });
});

// Đăng ký
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, profile } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Vui lòng điền đầy đủ thông tin' });
    }
    
    // Kiểm tra user đã tồn tại
    let existingUser;
    if (mongoose.connection.readyState === 1) {
      existingUser = await User.findOne({ $or: [{ username }, { email }] });
    } else {
      existingUser = users.find(u => u.username === username || u.email === email);
    }
    
    if (existingUser) {
      return res.status(400).json({ message: 'Tên đăng nhập hoặc email đã tồn tại' });
    }
    
    // Mã hóa mật khẩu
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    if (mongoose.connection.readyState === 1) {
      // Sử dụng MongoDB
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
      // Sử dụng dữ liệu tạm
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
      // Sử dụng MongoDB
      user = await User.findOne({ $or: [{ username }, { email: username }] });
      
      if (user) {
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          user = null;
        }
      }
    } else {
      // Sử dụng dữ liệu tạm
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
    
    // Tạo JWT token
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
      
      // Trả về thông tin user (không bao gồm password)
      const userWithoutPassword = user.toObject();
      delete userWithoutPassword.password;
      
      res.json(userWithoutPassword);
    } else {
      const user = users.find(u => u.id == userId);
      
      if (!user) {
        return res.status(404).json({ message: 'Không tìm thấy người dùng' });
      }
      
      // Trả về thông tin user (không bao gồm password)
      const userWithoutPassword = { ...user };
      delete userWithoutPassword.password;
      
      res.json(userWithoutPassword);
    }
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Lấy danh sách user (có phân trang)
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
      // Trả về danh sách user không bao gồm thông tin nhạy cảm
      const usersWithoutSensitiveInfo = users.map(user => {
        const { password, ...userWithoutPassword } = user;
        return userWithoutPassword;
      });
      
      // Phân trang cho dữ liệu tạm
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

// Lấy danh sách bạn bè
app.get('/api/user/:id/friends', authenticateToken, async (req, res) => {
  try {
    const userId = req.params.id;
    
    if (mongoose.connection.readyState === 1) {
      const user = await User.findById(userId).populate('friends', '-password');
      if (!user) {
        return res.status(404).json({ message: 'Không tìm thấy người dùng' });
      }
      
      res.json(user.friends);
    } else {
      const user = users.find(u => u.id == userId);
      
      if (!user) {
        return res.status(404).json({ message: 'Không tìm thấy người dùng' });
      }
      
      // Lấy thông tin chi tiết của bạn bè
      const friends = users
        .filter(u => user.friends.includes(u.id))
        .map(friend => {
          const { password, ...friendWithoutPassword } = friend;
          return friendWithoutPassword;
        });
      
      res.json(friends);
    }
  } catch (error) {
    console.error('Get friends error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Gửi lời mời kết bạn
app.post('/api/friend-request/:userId', authenticateToken, async (req, res) => {
  try {
    const targetUserId = req.params.userId;
    const senderId = req.user.userId;
    
    if (mongoose.connection.readyState === 1) {
      const targetUser = await User.findById(targetUserId);
      if (!targetUser) {
        return res.status(404).json({ message: 'Người dùng không tồn tại' });
      }
      
      const sender = await User.findById(senderId);
      if (!sender) {
        return res.status(404).json({ message: 'Người dùng không tồn tại' });
      }
      
      if (!targetUser.friends.includes(senderId)) {
        targetUser.friends.push(senderId);
        await targetUser.save();
      }
      
      if (!sender.friends.includes(targetUserId)) {
        sender.friends.push(targetUserId);
        await sender.save();
      }
      
      res.json({ message: 'Đã gửi lời mời kết bạn thành công' });
    } else {
      const targetUser = users.find(u => u.id == targetUserId);
      if (!targetUser) {
        return res.status(404).json({ message: 'Người dùng không tồn tại' });
      }
      
      const sender = users.find(u => u.id == senderId);
      
      if (!targetUser.friends.includes(senderId)) {
        targetUser.friends.push(senderId);
      }
      
      if (!sender.friends.includes(targetUserId)) {
        sender.friends.push(targetUserId);
      }
      
      res.json({ message: 'Đã gửi lời mời kết bạn thành công' });
    }
  } catch (error) {
    console.error('Friend request error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Lấy danh sách bài post (có phân trang)
app.get('/api/posts', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    if (mongoose.connection.readyState === 1) {
      const posts = await Post.find()
        .populate('userId', 'username profile')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit);
      
      const total = await Post.countDocuments();
      
      res.json({
        posts,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      });
    } else {
      // Sắp xếp bài post theo thời gian mới nhất
      const sortedPosts = [...posts].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      
      // Thêm thông tin user vào mỗi bài post
      const postsWithUserInfo = sortedPosts.map(post => {
        const user = users.find(u => u.id === post.userId);
        return {
          ...post,
          user: {
          id: user.id,
          username: user.username,
          profile: user.profile
          }
        };
      });
      
      // Phân trang cho dữ liệu tạm
      const startIndex = skip;
      const endIndex = startIndex + limit;
      const paginatedPosts = postsWithUserInfo.slice(startIndex, endIndex);
      
      res.json({
        posts: paginatedPosts,
        pagination: {
          page,
          limit,
          total: posts.length,
          pages: Math.ceil(posts.length / limit)
        }
      });
    }
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Tạo bài post mới
app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { content, image } = req.body;
    const userId = req.user.userId;
    
    if (!content || content.trim() === '') {
      return res.status(400).json({ message: 'Nội dung không được để trống' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const newPost = new Post({
        userId,
        content: content.trim(),
        image: image || null,
        likes: [],
        comments: []
      });
      
      const savedPost = await newPost.save();
      const populatedPost = await Post.findById(savedPost._id).populate('userId', 'username profile');
      
      res.status(201).json(populatedPost);
    } else {
      const newPost = {
        id: nextPostId++,
        userId,
        content: content.trim(),
        image: image || null,
        likes: [],
        comments: [],
        createdAt: new Date()
      };
      
      posts.push(newPost);
      
      // Thêm thông tin user vào bài post vừa tạo
      const user = users.find(u => u.id === userId);
      const postWithUserInfo = {
        ...newPost,
        user: {
          id: user.id,
          username: user.username,
          profile: user.profile
        }
      };
      
      res.status(201).json(postWithUserInfo);
    }
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Like/unlike bài post
app.post('/api/posts/:postId/like', authenticateToken, async (req, res) => {
  try {
    const postId = req.params.postId;
    const userId = req.user.userId;
    
    if (mongoose.connection.readyState === 1) {
      const post = await Post.findById(postId);
      if (!post) {
        return res.status(404).json({ message: 'Bài post không tồn tại' });
      }
      
      const likeIndex = post.likes.indexOf(userId);
      
      if (likeIndex === -1) {
        // Like bài post
        post.likes.push(userId);
        await post.save();
        res.json({ message: 'Đã like bài post', liked: true, likes: post.likes.length });
      } else {
        // Unlike bài post
        post.likes.splice(likeIndex, 1);
        await post.save();
        res.json({ message: 'Đã unlike bài post', liked: false, likes: post.likes.length });
      }
    } else {
      const post = posts.find(p => p.id == postId);
      if (!post) {
        return res.status(404).json({ message: 'Bài post không tồn tại' });
      }
      
      const likeIndex = post.likes.indexOf(userId);
      
      if (likeIndex === -1) {
        // Like bài post
        post.likes.push(userId);
        res.json({ message: 'Đã like bài post', liked: true, likes: post.likes.length });
      } else {
        // Unlike bài post
        post.likes.splice(likeIndex, 1);
        res.json({ message: 'Đã unlike bài post', liked: false, likes: post.likes.length });
      }
    }
  } catch (error) {
    console.error('Like post error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Thêm comment vào bài post
app.post('/api/posts/:postId/comment', authenticateToken, async (req, res) => {
  try {
    const postId = req.params.postId;
    const userId = req.user.userId;
    const { content } = req.body;
    
    if (!content || content.trim() === '') {
      return res.status(400).json({ message: 'Nội dung comment không được để trống' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const post = await Post.findById(postId);
      if (!post) {
        return res.status(404).json({ message: 'Bài post không tồn tại' });
      }
      
      const newComment = {
        userId,
        content: content.trim(),
        createdAt: new Date()
      };
      
      post.comments.push(newComment);
      await post.save();
      
      // Populate user info for the comment
      const populatedPost = await Post.findById(postId)
        .populate('comments.userId', 'username profile');
      
      const addedComment = populatedPost.comments[populatedPost.comments.length - 1];
      res.status(201).json(addedComment);
    } else {
      const post = posts.find(p => p.id == postId);
      if (!post) {
        return res.status(404).json({ message: 'Bài post không tồn tại' });
      }
      
      const newComment = {
        id: Date.now(),
        userId,
        content: content.trim(),
        createdAt: new Date()
      };
      
      post.comments.push(newComment);
      
      // Thêm thông tin user vào comment
      const user = users.find(u => u.id === userId);
      const commentWithUserInfo = {
        ...newComment,
        user: {
          id: user.id,
          username: user.username,
          profile: user.profile
        }
      };
      
      res.status(201).json(commentWithUserInfo);
    }
  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Cập nhật thông tin profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { fullname, age, gender, bio, interests, avatar } = req.body;
    
    if (mongoose.connection.readyState === 1) {
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: 'Người dùng không tồn tại' });
      }
      
      user.profile = {
        fullname: fullname || user.profile.fullname,
        age: age !== undefined ? parseInt(age) : user.profile.age,
        gender: gender || user.profile.gender,
        bio: bio || user.profile.bio,
        interests: interests || user.profile.interests,
        avatar: avatar || user.profile.avatar
      };
      
      const updatedUser = await user.save();
      res.json({ message: 'Cập nhật profile thành công', profile: updatedUser.profile });
    } else {
      const user = users.find(u => u.id == userId);
      if (!user) {
        return res.status(404).json({ message: 'Người dùng không tồn tại' });
      }
      
      user.profile = {
        fullname: fullname || user.profile.fullname,
        age: age !== undefined ? parseInt(age) : user.profile.age,
        gender: gender || user.profile.gender,
        bio: bio || user.profile.bio,
        interests: interests || user.profile.interests,
        avatar: avatar || user.profile.avatar
      };
      
      res.json({ message: 'Cập nhật profile thành công', profile: user.profile });
    }
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Gửi tin nhắn
app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { receiverId, content } = req.body;
    const senderId = req.user.userId;
    
    if (!receiverId || !content || content.trim() === '') {
      return res.status(400).json({ message: 'Thiếu thông tin người nhận hoặc nội dung tin nhắn' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const newMessage = new Message({
        senderId,
        receiverId,
        content: content.trim(),
        isRead: false
      });
      
      const savedMessage = await newMessage.save();
      const populatedMessage = await Message.findById(savedMessage._id)
        .populate('senderId', 'username profile')
        .populate('receiverId', 'username profile');
      
      res.status(201).json(populatedMessage);
    } else {
      const newMessage = {
        id: nextMessageId++,
        senderId,
        receiverId,
        content: content.trim(),
        isRead: false,
        createdAt: new Date()
      };
      
      messages.push(newMessage);
      
      // Thêm thông tin user vào tin nhắn
      const sender = users.find(u => u.id === senderId);
      const receiver = users.find(u => u.id === receiverId);
      
      const messageWithUserInfo = {
        ...newMessage,
        sender: {
          id: sender.id,
          username: sender.username,
          profile: sender.profile
        },
        receiver: {
          id: receiver.id,
          username: receiver.username,
          profile: receiver.profile
        }
      };
      
      res.status(201).json(messageWithUserInfo);
    }
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Lấy tin nhắn giữa hai người
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
  try {
    const otherUserId = req.params.userId;
    const currentUserId = req.user.userId;
      
    if (mongoose.connection.readyState === 1) {
      const messageList = await Message.find({
        $or: [
          { senderId: currentUserId, receiverId: otherUserId },
          { senderId: otherUserId, receiverId: currentUserId }
        ]
      })
      .populate('senderId', 'username profile')
      .populate('receiverId', 'username profile')
      .sort({ createdAt: 1 });
      
      res.json(messageList);
    } else {
      const messageList = messages.filter(msg => 
        (msg.senderId == currentUserId && msg.receiverId == otherUserId) ||
        (msg.senderId == otherUserId && msg.receiverId == currentUserId)
      ).sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
      
      // Thêm thông tin user vào tin nhắn
      const messagesWithUserInfo = messageList.map(msg => {
        const sender = users.find(u => u.id === msg.senderId);
        const receiver = users.find(u => u.id === msg.receiverId);
        
        return {
          ...msg,
          sender: {
            id: sender.id,
            username: sender.username,
            profile: sender.profile
          },
          receiver: {
            id: receiver.id,
            username: receiver.username,
            profile: receiver.profile
          }
        };
      });
      
      res.json(messagesWithUserInfo);
    }
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Route mặc định - phục vụ trang chủ
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Route cho các trang
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/trang-chu', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'trang-chu.html'));
});

app.get('/dang-ky', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dang-ky.html'));
});

app.get('/test', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'test.html'));
});

// Route fallback cho SPA (Single Page Application)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Xử lý lỗi toàn cục
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