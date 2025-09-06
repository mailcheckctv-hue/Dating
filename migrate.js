const mongoose = require('mongoose');
const User = require('./models/User');
require('dotenv').config();

async function migrate(){
  await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/loveconnect');
  console.log('Connected to MongoDB');
  const users = await User.find();
  for (let u of users){
    u.phone = u.phone || '';
    u.income = u.income || '';
    u.job = u.job || '';
    if (typeof u.sentToday !== 'number') u.sentToday = 0;
    if (typeof u.dailyLimit !== 'number') u.dailyLimit = 0;
    if (typeof u.weeklyLimit !== 'number') u.weeklyLimit = 0;
    if (typeof u.monthlyLimit !== 'number') u.monthlyLimit = 0;
    if (typeof u.yearlyLimit !== 'number') u.yearlyLimit = 0;
    if (typeof u.isBanned !== 'boolean') u.isBanned = false;
    if (typeof u.smsBlocked !== 'boolean') u.smsBlocked = false;
    await u.save();
    console.log('Updated user', u._id);
  }
  console.log('Migration complete.');
  process.exit();
}
migrate();
