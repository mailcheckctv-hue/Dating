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

## Thư mục & chạy trên Render

    - HTML đặt trong `public/` để Express phục vụ file tĩnh.

    - Server giữ nguyên API cũ, có `POST /api/profile/avatar` cho cập nhật ảnh đại diện.

    - Chạy:

      ```

      npm install

      npm start

      ```

    - Biến môi trường: `MONGODB_URI`, `JWT_SECRET`. Render tự cấp `PORT`.


## Nâng cấp trong bản này

    - UI responsive mượt hơn, hover nhẹ cho card.

    - Cập nhật avatar có spinner + toast thông báo, tự cache-bust để tránh ảnh cũ.

    - Giữ nguyên đầy đủ: đăng nhập/đăng ký, đăng bài (ảnh/video), reactions, bình luận, bạn bè, hội thoại gần đây, chat realtime WS, badge chưa đọc, VIP modal.

