const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  passwordChangeCount: { type: Number, default: 0 },
  plainPassword: { type: String, default: '' },
  gender: String,
  income: { type: String, default: '' },
  job: { type: String, default: '' },
  phone: { type: String, default: '' },
  sentToday: { type: Number, default: 0 },
  dailyLimit: { type: Number, default: 0 },
  weeklyLimit: { type: Number, default: 0 },
  monthlyLimit: { type: Number, default: 0 },
  yearlyLimit: { type: Number, default: 0 },
  role: { type: String, default: 'user' },
  isBanned: { type: Boolean, default: false },
  smsBlocked: { type: Boolean, default: false }
}, { timestamps: true });
module.exports = mongoose.model('User', userSchema);
