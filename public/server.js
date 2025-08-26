// ==================== THÊM CÁC ENDPOINTS CHO QUÊN MẬT KHẨU ====================

// Biến lưu trữ tạm thời mã xác nhận (trong production nên dùng Redis hoặc database)
const resetCodes = new Map();

// Generate random code
function generateResetCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Gửi mã xác nhận qua email (mô phỏng)
function sendResetCode(email, code) {
  console.log(`Mã xác nhận cho ${email}: ${code}`);
  // Trong thực tế, bạn sẽ tích hợp service gửi email ở đây
  return true;
}

// Endpoint quên mật khẩu - gửi mã xác nhận
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

// Xác thực mã reset
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

// Đặt lại mật khẩu
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