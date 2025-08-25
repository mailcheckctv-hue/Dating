require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;

// ✅ KHAI BÁO BIẾN TRƯỚC KHI SỬ DỤNG
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://datingappuser:95485675@cluster0.hsl2eh4.mongodb.net/dating-app?retryWrites=true&w=majority&appName=Cluster0';

// ✅ SỬ DỤNG BIẾN SAU KHI ĐÃ KHAI BÁO
console.log('🔄 Đang kết nối đến MongoDB...');
console.log('📝 URI from env:', process.env.MONGODB_URI ? 'Exists' : 'Missing');
console.log('📝 Using URI:', MONGODB_URI.replace(/:[^:]*@/, ':****@'));

// ✅ KẾT NỐI MONGODB
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('✅ Đã kết nối đến MongoDB thành công!');
    console.log('📊 Database:', mongoose.connection.name);
  })
  .catch(err => {
    console.log('❌ Lỗi kết nối MongoDB, sử dụng fallback mode...');
    console.log('💡 Lỗi:', err.message);
  });

// ... (phần còn lại của code) ...