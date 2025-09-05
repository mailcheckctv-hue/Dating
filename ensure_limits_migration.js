
/**
 * ensure_limits_migration.js
 * Usage: node ensure_limits_migration.js --uri "mongodb://..." [--dry]
 *
 * This script will scan the `users` collection and ensure each user document has:
 *  - dailyLimit (default 5)
 *  - dailySent (default 0)
 *  - dailyResetAt (default next midnight UTC)
 *
 * IMPORTANT: run with --dry to preview changes; always backup DB before running.
 */
const { MongoClient } = require('mongodb');
const argv = require('yargs').argv;

const MONGODB_URI = argv.uri || process.env.MONGODB_URI;
const DRY = argv.dry || false;

if(!MONGODB_URI){
  console.error('Missing --uri or MONGODB_URI');
  process.exit(1);
}

function nextMidnightUTC(date=new Date()){
  const d = new Date(date);
  d.setUTCHours(24,0,0,0);
  return d;
}

(async ()=>{
  const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  try{
    await client.connect();
    const db = client.db();
    const users = db.collection('users');
    const cursor = users.find({ $or: [ { dailyLimit: { $exists: false } }, { dailyResetAt: { $exists: false } }, { dailySent: { $exists: false } } ] });
    const ops = [];
    while(await cursor.hasNext()){
      const u = await cursor.next();
      const set = {};
      if(u.dailyLimit === undefined) set.dailyLimit = 5;
      if(u.dailySent === undefined) set.dailySent = 0;
      if(u.dailyResetAt === undefined) set.dailyResetAt = nextMidnightUTC();
      if(Object.keys(set).length){
        ops.push({ id: u._id, set });
      }
    }
    console.log(`Found ${ops.length} users to update.`);
    if(ops.length === 0){ process.exit(0); }
    if(DRY){
      console.log('DRY RUN - the following would be applied:');
      console.log(JSON.stringify(ops, null, 2));
      process.exit(0);
    }
    for(const o of ops){
      await users.updateOne({ _id: o.id }, { $set: o.set });
      console.log('Updated', o.id.toString(), o.set);
    }
    console.log('Done.');
  }catch(e){
    console.error(e);
  }finally{
    await client.close();
  }
})();
