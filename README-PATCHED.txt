Deployment-ready zip with Phase 1 features added (admin default, roles, daily SMS limits, helpers, admin API endpoints, WS check).
Files:
- server.patched.js : modified server file (do NOT overwrite original server.js until tested)
- All original files included so you can compare and replace manually.
Instructions:
1) Backup your DB.
2) Replace server.js with server.patched.js (or copy as server.js).
3) Ensure env vars: MONGODB_URI, JWT_SECRET are set.
4) npm install (if needed), then node server.js
5) Test login for default admin: email=admin_check_1@local or use the created id printed in console; password=87787323
6) Use admin endpoints to set/reset limits.
Notes:
- This patch focuses on Giai đoạn 1 (core). Further stages need more work.
