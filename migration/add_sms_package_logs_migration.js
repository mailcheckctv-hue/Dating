// Migration: create sms_package_logs collection (MongoDB) or ensure data folder exists for fallback JSON.
// Run with: node migration/add_sms_package_logs_migration.js
const fs = require('fs');
const path = require('path');

(async function(){
  try{
    // Try MongoDB if MONGO_URI exists
    const uri = process.env.MONGO_URI || '';
    if(uri){
      const {MongoClient} = require('mongodb');
      const client = new MongoClient(uri, { useNewUrlParser:true, useUnifiedTopology:true });
      await client.connect();
      const db = client.db(process.env.MONGO_DB || 'test');
      const colNames = await db.listCollections({name:'sms_package_logs'}).toArray();
      if(colNames.length===0){
        await db.createCollection('sms_package_logs');
        console.log('Created collection sms_package_logs');
      } else console.log('sms_package_logs exists');
      await client.close();
    } else {
      const dataDir = path.join(process.cwd(),'data');
      if(!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
      const f = path.join(dataDir,'sms_package_logs.json');
      if(!fs.existsSync(f)) fs.writeFileSync(f,'[]','utf8');
      console.log('Created data/sms_package_logs.json (fallback)');
    }
  }catch(e){
    console.error('Migration failed', e);
    process.exit(1);
  }
})();
