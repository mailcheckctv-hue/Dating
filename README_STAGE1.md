
# Giai đoạn 1 – Triển khai tính năng quản trị & hạn mức

Cập nhật ngày: 2025-09-05

## Tổng quan
Gói cập nhật này bổ sung/hoàn thiện các tính năng core:
- Tài khoản admin mặc định **Admin_Check_1 / 87787323** (đã có sẵn trong `server.js` thông qua `ensureDefaultAdmin()`).
- Phân quyền cơ bản qua trường `role` (guest/user/moderator/admin/superadmin).
- Hạn mức tin nhắn theo ngày (`dailyLimit`, `dailySent`, `dailyResetAt`) + tự reset qua `resetIfNeeded()`.
- **WS check quota realtime**: thêm helper **`checkDailyLimit(userId, ws?)`** (alias của `tryConsumeDaily`) dùng trong WebSocket hoặc nơi khác.
- **API lấy hạn mức**: `GET /api/profile/limits` để hiển thị "đã gửi hôm nay / hạn mức" trên UI.
- **Đăng nhập bằng email/username/ID**: `/api/login` đã hỗ trợ `identifier`. File `login.html` cập nhật cho phép nhập 1 trường chung.
- **Admin quản lý user**: `GET /api/admin/users`, `POST /api/admin/set-limit`, `POST /api/admin/reset-daily/:userId` đã sẵn sàng.

## Thay đổi database/schema
Sử dụng MongoDB (Mongoose). Trường trong `userSchema` (đã có):
```js
role: { type: String, enum: ['guest','user','moderator','admin','superadmin'], default: 'user' },
dailyLimit: { type: Number, default: 5 },
dailySent: { type: Number, default: 0 },
dailyResetAt: { type: Date, default: () => { const d = new Date(); d.setHours(24,0,0,0); return d; } },
isLocked: { type: Boolean, default: false }
```
> Nếu dữ liệu cũ thiếu các trường trên, chạy script `node ensure_limits_migration.js --uri "<MONGODB_URI>"` để backfill.

## Endpoints Giai đoạn 1
- `POST /api/register` — đăng ký cơ bản.
- `POST /api/login` — đăng nhập bằng `{ id | email | username | identifier } + password`.
- `GET /api/profile` — lấy thông tin user hiện tại.
- **`GET /api/profile/limits`** — lấy `{ dailySent, dailyLimit, dailyResetAt, remaining }`.
- `GET /api/admin/users` — danh sách user (admin/superadmin).
- `POST /api/admin/set-limit` — body: `{ "userId": "<id>", "limit": 20 }`.
- `POST /api/admin/reset-daily/:userId` — reset bộ đếm cho 1 user.
- WebSocket: gửi tin sẽ kiểm tra hạn mức bằng `tryConsumeDaily()` (và có thể dùng alias `checkDailyLimit(userId, ws)` mới).

## Hướng dẫn tích hợp
1. **Cấu hình**: đảm bảo các biến môi trường `MONGODB_URI`, `JWT_SECRET` tồn tại trên Render.
2. **Triển khai**: nạp zip này, cài dependencies (`npm i`), chạy `node server.js`.
3. **Admin mặc định**: server sẽ tự tạo Admin_Check_1 nếu chưa tồn tại và gán `role: 'admin'`.
4. **UI**:
   - `login.html` cho phép nhập Email/Username/ID, lưu token ở `localStorage.token` (đồng thời `authToken` để tương thích).
   - `profile.html` hiển thị **Đã gửi hôm nay / Hạn mức** qua `GET /api/profile/limits`.
5. **Backward compatibility**: không thay đổi API hiện có; chỉ **bổ sung** endpoint mới và helper alias.

## Kiểm thử nhanh (ví dụ)
```bash
# Đăng nhập
curl -X POST http://localhost:10000/api/login -H "Content-Type: application/json"   -d '{ "identifier": "Admin_Check_1", "password": "87787323" }'

# Lấy hạn mức
curl -H "Authorization: Bearer <TOKEN>" http://localhost:10000/api/profile/limits

# Đặt hạn mức 20 tin/ngày cho USER_ID
curl -X POST http://localhost:10000/api/admin/set-limit -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json"   -d '{ "userId": "<USER_ID>", "limit": 20 }'

# Reset bộ đếm cho USER_ID
curl -X POST http://localhost:10000/api/admin/reset-daily/<USER_ID> -H "Authorization: Bearer <TOKEN)"
```

## Lưu ý bảo mật
- Nhớ thay `JWT_SECRET` trong môi trường production.
- Tài khoản admin mặc định nên **đổi password** sau khi deploy.
- Giới hạn tin nhắn: admin/superadmin **không bị giới hạn** theo thiết kế.

---
*Được đóng gói sẵn để deploy Render nhanh chóng.*
