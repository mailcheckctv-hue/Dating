# LoveConnect - Triển khai nhanh trên Render

## Biến môi trường
- `MONGODB_URI`: chuỗi kết nối MongoDB
- `JWT_SECRET`: khóa bí mật JWT
- `PORT`: Render sẽ tự đặt, nhớ dùng `process.env.PORT`

## Chạy
```
npm install
npm start
```

## Thư mục tĩnh
- Đặt `login.html`, `dang-ky.html`, `trang-chu.html` vào thư mục `public/` nếu muốn server phục vụ trực tiếp.
- Hiện bản này phục vụ file tĩnh ở thư mục `public` nếu tồn tại.
