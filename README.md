# SMS Package Management — Patch & Files

This package contains frontend and server patches to add admin SMS package granting and logs.

Files included:
- admin-sms-packages.html  — Admin UI (responsive, basic light/dark toggle)
- server-sms-package-patch.js — Express route registration (defensive)
- migration/add_sms_package_logs_migration.js — Migration helper to create collection or fallback file
- curl_tests.sh — curl test script
- README.md — this file

## Quick integration steps

1. Put `admin-sms-packages.html` into your `public/admin/` (or equivalent) folder so it is served (e.g. `/admin/admin-sms-packages.html`).

2. Integrate the server patch into your Express app.
   In your `server.patched.js` (or main server file), add near your route registrations:

```js
const registerSmsPackageRoutes = require('./server-sms-package-patch');
const db = /* your mongodb db object or null */;
const requireAdmin = /* your middleware that ensures admin auth */;
registerSmsPackageRoutes(app, { db, requireAdmin, getAdminIdFromReq: req => req.user && req.user.id });
```

If your app does not use MongoDB, the patch will fallback to a JSON-file based store under `data/sms_package_logs.json` and `data/users.json`.

3. Run migration (optional):
```
node migration/add_sms_package_logs_migration.js
```

4. Update database schema:
- If using MongoDB: `sms_package_logs` collection with documents `{ userId, qty, adminId, note?, createdAt }`.
- If using SQL: create an equivalent table — see schema below.

SQL example (Postgres):
```sql
CREATE TABLE sms_package_logs (
  id SERIAL PRIMARY KEY,
  user_id TEXT NOT NULL,
  qty INTEGER NOT NULL,
  admin_id TEXT,
  note TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);
```

5. Test using `curl_tests.sh`. Set `BASE_URL` and `AUTH_HEADER` appropriately.

## Security / performance notes
- Ensure `requireAdmin` protects these endpoints.
- Limit returned results and paginate in production.
- Sanitize/validate inputs carefully if integrating into a larger codebase.
- If you use MongoDB, create an index on `{ userId:1, createdAt:-1 }` for history queries.

## Packaging
A zip is included with these files for quick upload/deploy.

If you want, I can merge the patch directly into your `server.patched.js` (paste the file here) and adapt the routes exactly to your codebase.
