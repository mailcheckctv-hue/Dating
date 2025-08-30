# LoveConnect (build đã tối ưu giao diện + tính năng mới)

## Cấu trúc
- server.js (đã có API: upload avatar, posts image-first, friends, conversations, unread badge)
- public/login.html, public/dang-ky.html, public/trang-chu.html

## Triển khai Render
1) Thiết lập biến môi trường: MONGODB_URI, JWT_SECRET
2) Build & Run:
   ```
   npm install
   npm start
   ```
Render sẽ tự dùng `PORT`.

## Ghi chú
- Ảnh/Video trong feed hiển thị đúng định dạng; nếu URL ảnh cũ không có đuôi, UI sẽ thử load ảnh trước, nếu lỗi sẽ thay bằng link tải.
- Icon chuông ở navbar hiển thị số tin nhắn chưa đọc. Khi có WS tin nhắn mới sẽ tự tăng badge.
- Kết bạn: sau khi bấm “Thêm bạn” nút chuyển trạng thái, có thể nhắn tin ngay.
- Cập nhật ảnh đại diện: click biểu tượng máy ảnh trong thẻ hồ sơ.