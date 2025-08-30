# LoveConnect (Updated)

## Điểm mới
- UI Bootstrap hiện đại, tối ưu mobile/desktop
- Cập nhật ảnh đại diện bằng biểu tượng máy ảnh
- Hiển thị đúng định dạng Ảnh/Video trong feed và chat
- Kết bạn -> có thể nhắn tin (nút Nhắn luôn hiển thị)
- Chuông thông báo trên navbar hiển thị số tin nhắn chưa đọc (real-time + polling)
- Form Đăng nhập/Đăng ký thiết kế chuyên nghiệp
- Đăng ký thêm trường **Thu nhập** và **Công việc**
- API giữ nguyên tương thích, thêm `job` trong schema và nhận `income`, `job` ở `/api/register`

## Triển khai trên Render
1. Thiết lập biến môi trường: `MONGODB_URI`, `JWT_SECRET`
2. `npm install` rồi `npm start`
3. Thư mục tĩnh: các file HTML nằm trong `public/`

## Cấu trúc
- `server.js` – API + WebSocket
- `public/login.html`, `public/dang-ky.html`, `public/trang-chu.html`
