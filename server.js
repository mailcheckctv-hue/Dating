require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Phục vụ file tĩnh từ thư mục public (một cấp trên thư mục hiện tại)
app.use(express.static(path.join(__dirname, '../public')));

// Kết nối MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/datingapp';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Đã kết nối đến MongoDB'))
.catch(err => {
  console.error('Lỗi kết nối MongoDB:', err);
  console.log('Sử dụng dữ liệu tạm thời...');
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
    interests: [String]
  },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const PostSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    content: String,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);

// Dữ liệu tạm thời (sử dụng khi không kết nối được MongoDB)
let users = [];
let posts = [];
let nextId = 1;
let nextPostId = 1;

// Middleware xác thực JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Token truy cập không tồn tại' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'dating_app_secret_key', (err, decoded) => {
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
        process.env.JWT_SECRET || 'dating_app_secret_key', 
        { expiresIn: '24h' }
      );
      
      res.status(201).json({ 
        message: 'Đăng ký thành công',
        token,
        user: {
          id: newUser._id,
          username: newUser.username,
          email: newUser.email
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
        process.env.JWT_SECRET || 'dating_app_secret_key', 
        { expiresIn: '24h' }
      );
      
      res.status(201).json({ 
        message: 'Đăng ký thành công',
        token,
        user: {
          id: newUser.id,
          username: newUser.username,
          email: newUser.email
        }
      });
    }
  } catch (error) {
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
      process.env.JWT_SECRET || 'dating_app_secret_key', 
      { expiresIn: '24h' }
    );
    
    res.json({ 
      token, 
      user: { 
        id: mongoose.connection.readyState === 1 ? user._id : user.id, 
        username: user.username,
        email: user.email
      },
      message: 'Đăng nhập thành công'
    });
  } catch (error) {
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Kiểm tra token
app.get('/api/check-auth', authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;
    
    if (mongoose.connection.readyState === 1) {
      User.findById(userId, (err, user) => {
        if (err || !user) {
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
            email: user.email
          }
        });
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
          email: user.email
        }
      });
    }
  } catch (error) {
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Lấy thông tin user
app.get('/api/user/:id', authenticateToken, (req, res) => {
  try {
    const userId = req.params.id;
    
    if (mongoose.connection.readyState === 1) {
      User.findById(userId, (err, user) => {
        if (err || !user) {
          return res.status(404).json({ message: 'Không tìm thấy người dùng' });
        }
        
        // Trả về thông tin user (không bao gồm password)
        const userWithoutPassword = user.toObject();
        delete userWithoutPassword.password;
        
        res.json(userWithoutPassword);
      });
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
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Lấy danh sách user
app.get('/api/users', authenticateToken, (req, res) => {
  try {
    if (mongoose.connection.readyState === 1) {
      User.find({}, '-password', (err, users) => {
        if (err) {
          return res.status(500).json({ message: 'Lỗi server', error: err.message });
        }
        
        res.json(users);
      });
    } else {
      // Trả về danh sách user không bao gồm thông tin nhạy cảm
      const usersWithoutSensitiveInfo = users.map(user => {
        const { password, ...userWithoutPassword } = user;
        return userWithoutPassword;
      });
      
      res.json(usersWithoutSensitiveInfo);
    }
  } catch (error) {
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Lấy danh sách bạn bè
app.get('/api/user/:id/friends', authenticateToken, (req, res) => {
  try {
    const userId = req.params.id;
    
    if (mongoose.connection.readyState === 1) {
      User.findById(userId).populate('friends', '-password').exec((err, user) => {
        if (err || !user) {
          return res.status(404).json({ message: 'Không tìm thấy người dùng' });
        }
        
        res.json(user.friends);
      });
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
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Gửi lời mời kết bạn
app.post('/api/friend-request/:userId', authenticateToken, (req, res) => {
  try {
    const targetUserId = req.params.userId;
    const senderId = req.user.userId;
    
    if (mongoose.connection.readyState === 1) {
      User.findById(targetUserId, (err, targetUser) => {
        if (err || !targetUser) {
          return res.status(404).json({ message: 'Người dùng không tồn tại' });
        }
        
        User.findById(senderId, (err, sender) => {
          if (err || !sender) {
            return res.status(404).json({ message: 'Người dùng không tồn tại' });
          }
          
          if (!targetUser.friends.includes(senderId)) {
            targetUser.friends.push(senderId);
            targetUser.save();
          }
          
          if (!sender.friends.includes(targetUserId)) {
            sender.friends.push(targetUserId);
            sender.save();
          }
          
          res.json({ message: 'Đã gửi lời mời kết bạn thành công' });
        });
      });
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
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Lấy danh sách bài post
app.get('/api/posts', authenticateToken, (req, res) => {
  try {
    if (mongoose.connection.readyState === 1) {
      Post.find().populate('userId', 'username profile').exec((err, posts) => {
        if (err) {
          return res.status(500).json({ message: 'Lỗi server', error: err.message });
        }
        
        // Sắp xếp bài post theo thời gian mới nhất
        const sortedPosts = posts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        
        res.json(sortedPosts);
      });
    } else {
      // Sắp xếp bài post theo thời gian mới nhất
      const sortedPosts = posts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      
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
      
      res.json(postsWithUserInfo);
    }
  } catch (error) {
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Tạo bài post mới
app.post('/api/posts', authenticateToken, (req, res) => {
  try {
    const { content } = req.body;
    const userId = req.user.userId;
    
    if (!content || content.trim() === '') {
      return res.status(400).json({ message: 'Nội dung không được để trống' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const newPost = new Post({
        userId,
        content: content.trim(),
        likes: [],
        comments: []
      });
      
      newPost.save((err, post) => {
        if (err) {
          return res.status(500).json({ message: 'Lỗi server', error: err.message });
        }
        
        Post.findById(post._id).populate('userId', 'username profile').exec((err, populatedPost) => {
          if (err) {
            return res.status(500).json({ message: 'Lỗi server', error: err.message });
          }
          
          res.status(201).json(populatedPost);
        });
      });
    } else {
      const newPost = {
        id: nextPostId++,
        userId,
        content: content.trim(),
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
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Like/unlike bài post
app.post('/api/posts/:postId/like', authenticateToken, (req, res) => {
  try {
    const postId = req.params.postId;
    const userId = req.user.userId;
    
    if (mongoose.connection.readyState === 1) {
      Post.findById(postId, (err, post) => {
        if (err || !post) {
          return res.status(404).json({ message: 'Bài post không tồn tại' });
        }
        
        const likeIndex = post.likes.indexOf(userId);
        
        if (likeIndex === -1) {
          // Like bài post
          post.likes.push(userId);
          post.save();
          res.json({ message: 'Đã like bài post', liked: true });
        } else {
          // Unlike bài post
          post.likes.splice(likeIndex, 1);
          post.save();
          res.json({ message: 'Đã unlike bài post', liked: false });
        }
      });
    } else {
      const post = posts.find(p => p.id == postId);
      if (!post) {
        return res.status(404).json({ message: 'Bài post không tồn tại' });
      }
      
      const likeIndex = post.likes.indexOf(userId);
      
      if (likeIndex === -1) {
        // Like bài post
        post.likes.push(userId);
        res.json({ message: 'Đã like bài post', liked: true });
      } else {
        // Unlike bài post
        post.likes.splice(likeIndex, 1);
        res.json({ message: 'Đã unlike bài post', liked: false });
      }
    }
  } catch (error) {
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Thêm comment vào bài post
app.post('/api/posts/:postId/comment', authenticateToken, (req, res) => {
  try {
    const postId = req.params.postId;
    const userId = req.user.userId;
    const { content } = req.body;
    
    if (!content || content.trim() === '') {
      return res.status(400).json({ message: 'Nội dung comment không được để trống' });
    }
    
    if (mongoose.connection.readyState === 1) {
      Post.findById(postId, (err, post) => {
        if (err || !post) {
          return res.status(404).json({ message: 'Bài post không tồn tại' });
        }
        
        const newComment = {
          userId,
          content: content.trim(),
          createdAt: new Date()
        };
        
        post.comments.push(newComment);
        post.save();
        
        // Populate user info for the comment
        Post.findById(postId).populate('comments.userId', 'username profile').exec((err, populatedPost) => {
          if (err) {
            return res.status(500).json({ message: 'Lỗi server', error: err.message });
          }
          
          const addedComment = populatedPost.comments[populatedPost.comments.length - 1];
          res.status(201).json(addedComment);
        });
      });
    } else {
      const post = posts.find(p => p.id == postId);
      if (!post) {
        return res.status(404).json({ message: 'Bài post không tồn tại' });
      }
      
      const newComment = {
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
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Cập nhật thông tin profile
app.put('/api/profile', authenticateToken, (req, res) => {
  try {
    const userId = req.user.userId;
    const { fullname, age, gender, bio, interests } = req.body;
    
    if (mongoose.connection.readyState === 1) {
      User.findById(userId, (err, user) => {
        if (err || !user) {
          return res.status(404).json({ message: 'Người dùng không tồn tại' });
        }
        
        user.profile = {
          fullname: fullname || user.profile.fullname,
          age: age !== undefined ? parseInt(age) : user.profile.age,
          gender: gender || user.profile.gender,
          bio: bio || user.profile.bio,
          interests: interests || user.profile.interests
        };
        
        user.save((err, updatedUser) => {
          if (err) {
            return res.status(500).json({ message: 'Lỗi server', error: err.message });
          }
          
          res.json({ message: 'Cập nhật profile thành công', profile: updatedUser.profile });
        });
      });
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
        interests: interests || user.profile.interests
      };
      
      res.json({ message: 'Cập nhật profile thành công', profile: user.profile });
    }
  } catch (error) {
    res.status(500).json({ message: 'Lỗi server', error: error.message });
  }
});

// Route mặc định - phục vụ trang chủ
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public', 'login.html'));
});

// Route cho các trang
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../public', 'login.html'));
});

app.get('/trang-chu', (req, res) => {
  res.sendFile(path.join(__dirname, '../public', 'trang-chu.html'));
});

app.get('/dang-ky', (req, res) => {
  res.sendFile(path.join(__dirname, '../public', 'dang-ky.html'));
});

// Khởi động server
app.listen(PORT, () => {
  console.log(`=== SERVER DATING APP ===`);
  console.log(`Server đang chạy trên port ${PORT}`);
  console.log(`Môi trường: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Kết nối MongoDB: ${mongoose.connection.readyState === 1 ? 'Thành công' : 'Thất bại'}`);
  console.log(`Phục vụ file tĩnh từ: ${path.join(__dirname, '../public')}`);
  console.log(`================================`);
});