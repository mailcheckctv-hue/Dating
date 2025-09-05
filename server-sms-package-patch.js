/*
Patch to add SMS package history endpoint and optional logging to MongoDB or fallback JSON file.
Drop this into your server codebase and require/import it from server.patched.js (or merge the handlers).
It expects an Express app, authentication middleware `requireAdmin`, and a `db` object available.
If you don't have MongoDB, the fallback will write to data/sms_package_logs.json.

API endpoints added:
POST /api/admin/consume-package
GET  /api/admin/sms-packages/history
GET  /api/admin/users    <-- example implementation if missing (safe, paginated)

This file is intentionally defensive to avoid breaking existing code.
*/

const fs = require('fs');
const path = require('path');

module.exports = function registerSmsPackageRoutes(app, options = {}) {
  // options: { db, requireAdmin, getAdminIdFromReq }
  const db = options.db || null;
  const requireAdmin = options.requireAdmin || ((req,res,next)=> next());
  const getAdminId = options.getAdminIdFromReq || ((req)=> (req.user && req.user.id) || 'unknown');

  // helper: persist log
  async function persistLog(entry){
    entry.createdAt = new Date().toISOString();
    if(db && db.collection){
      try{
        const col = db.collection('sms_package_logs');
        await col.insertOne(entry);
        return;
      }catch(e){
        console.error('mongo insert failed', e);
      }
    }
    // fallback: append to JSON file
    const dataDir = path.join(process.cwd(), 'data');
    if(!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
    const file = path.join(dataDir, 'sms_package_logs.json');
    let arr = [];
    try{
      if(fs.existsSync(file)) arr = JSON.parse(fs.readFileSync(file,'utf8')||'[]');
    }catch(e){ arr = []; }
    arr.push(entry);
    fs.writeFileSync(file, JSON.stringify(arr, null, 2), 'utf8');
  }

  // GET users — safe default if your app already has /api/admin/users, you can remove this handler.
  app.get('/api/admin/users', requireAdmin, async (req,res)=>{
    try{
      // if db available, query and project minimal fields
      if(db && db.collection){
        const col = db.collection('users');
        const users = await col.find({}, { projection: { password:0 } }).limit(100).toArray();
        return res.json(users);
      }
      // fallback: read from data/users.json
      const fallback = path.join(process.cwd(), 'data', 'users.json');
      if(fs.existsSync(fallback)){
        const users = JSON.parse(fs.readFileSync(fallback,'utf8')||'[]');
        return res.json(users.slice(0,100));
      }
      return res.json([]);
    }catch(e){
      console.error(e);
      res.status(500).json({ error: 'server error' });
    }
  });

  // POST consume-package
  app.post('/api/admin/consume-package', requireAdmin, expressJsonParser(), async (req,res)=>{
    try{
      const body = req.body || {};
      const userId = body.userId;
      const qty = parseInt(body.qty,10) || 0;
      const note = body.note || '';
      if(!userId || qty<=0) return res.status(400).json({ error: 'userId and qty>0 required' });

      // update user's sms balance — best-effort to support either Mongo or JSON store
      let success = false;
      let userObj = null;
      if(db && db.collection){
        const users = db.collection('users');
        const result = await users.findOneAndUpdate({ _id: userId }, { $inc: { smsBalance: qty } }, { returnDocument: 'after' });
        userObj = result.value || null;
        success = !!userObj;
      } else {
        // fallback JSON
        const usersFile = path.join(process.cwd(), 'data', 'users.json');
        let arr = [];
        if(fs.existsSync(usersFile)) arr = JSON.parse(fs.readFileSync(usersFile,'utf8')||'[]');
        const idx = arr.findIndex(u=> (u._id||u.id)==userId);
        if(idx!==-1){
          arr[idx].smsBalance = (arr[idx].smsBalance||0) + qty;
          userObj = arr[idx];
          fs.writeFileSync(usersFile, JSON.stringify(arr, null, 2), 'utf8');
          success = true;
        }
      }

      // persist log
      const adminId = getAdminId(req);
      await persistLog({ userId, qty, adminId, note });

      if(!success) return res.status(404).json({ error: 'user not found or update failed' });
      return res.json({ success:true, user: userObj });
    }catch(e){
      console.error(e);
      res.status(500).json({ error: 'server error' });
    }
  });

  // GET history
  app.get('/api/admin/sms-packages/history', requireAdmin, async (req,res)=>{
    try{
      // support simple query params: ?userId=...&limit=100
      const qUser = req.query.userId;
      const limit = Math.min(1000, parseInt(req.query.limit||100,10));
      if(db && db.collection){
        const col = db.collection('sms_package_logs');
        const filter = qUser ? { userId: qUser } : {};
        const rows = await col.find(filter).sort({ createdAt: -1 }).limit(limit).toArray();
        return res.json(rows);
      }
      const file = path.join(process.cwd(), 'data', 'sms_package_logs.json');
      let arr = [];
      if(fs.existsSync(file)) arr = JSON.parse(fs.readFileSync(file,'utf8')||'[]');
      if(qUser) arr = arr.filter(r=>r.userId==qUser);
      arr = arr.slice(-limit);
      return res.json(arr);
    }catch(e){
      console.error(e);
      res.status(500).json({ error: 'server error' });
    }
  });

  // Helper: ensure express json parser available
  function expressJsonParser(){
    // If app uses bodyParser or express.json already, return a pass-through middleware
    const bp = (req,res,next)=>{
      if(req.body) return next();
      // try to parse raw
      let raw = '';
      req.setEncoding('utf8');
      req.on('data', chunk=> raw += chunk);
      req.on('end', ()=>{
        try{ req.body = raw ? JSON.parse(raw) : {}; } catch(e){ req.body = {}; }
        next();
      });
    };
    return bp;
  }

};
