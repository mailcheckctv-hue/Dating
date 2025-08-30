# LoveConnect - Build v2
- Fix avatar/post fallback hiển thị.
- /api/friends lưu trạng thái bạn bè (mutual) trong Mongo.
- Thêm gửi Sticker trong chat (tray twemoji) + hỗ trợ stickerUrl trên WebSocket/DB.
- Thêm bộ đếm tổng số tin nhắn (kim cương 💎) qua `/api/messages/total-count`.
- Cổng VIP: chỉ tài khoản VIP mới gửi được tin nhắn (server & client). API /api/upgrade-vip để set VIP.