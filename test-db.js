const mongoose = require('mongoose');

async function testDB() {
  try {
    console.log('Đang test kết nối MongoDB...');
    
    await mongoose.connect('mongodb://127.0.0.1:27017/datingapp', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    console.log('✅ Kết nối thành công!');
    
    // Kiểm tra xem database có tồn tại không
    const dbs = await mongoose.connection.db.admin().listDatabases();
    console.log('Databases:', dbs.databases.map(db => db.name));
    
    await mongoose.connection.close();
    console.log('Đã đóng kết nối');
    
  } catch (error) {
    console.error('❌ Lỗi kết nối:');
    console.error('Message:', error.message);
    console.error('Code:', error.code);
    console.log('\n💡 Gợi ý khắc phục:');
    console.log('1. Kiểm tra MongoDB có đang chạy không');
    console.log('2. Chạy lệnh: mongod (trong Command Prompt)');
    console.log('3. Đảm bảo port 27017 không bị block');
  }
}

testDB();