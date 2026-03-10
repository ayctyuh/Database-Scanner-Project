# DbScanner

Công cụ quét và đánh giá bảo mật cơ sở dữ liệu MySQL, tự động phát hiện các lỗ hổng cấu hình và đưa ra khuyến nghị khắc phục. Được xây dựng bằng Python với giao diện web trực quan, hỗ trợ kết nối SSL/TLS.

---

## Tính năng

- Giao diện tối giản: trang kết nối gọn nhẹ, báo cáo dạng bảng điều khiển với số liệu tổng quan và danh sách phát hiện dạng accordion.
- Bộ kiểm tra mặc định (MySQL/MariaDB):
  - Chính sách mật khẩu (`validate_password`, chiều dài, chữ hoa/thường, chữ số, ký tự đặc biệt).
  - Thiết lập kênh truyền (`require_secure_transport`, `local_infile`, `skip_grant_tables`).
  - Đặc quyền toàn cục nguy hiểm, tài khoản không mật khẩu, tài khoản ẩn danh, root đăng nhập từ xa.
  - Biến cấu hình nhạy cảm (`secure_file_priv`, `default_password_lifetime`, `sql_mode`, ...).
  - Ghi nhận kiểm tra bị bỏ qua (ví dụ thiếu quyền đọc `mysql.user`).
- Kết quả sắp xếp theo mức độ rủi ro (Critical, High, Medium, Low, Info) kèm khuyến nghị xử lý.
- Có thể chạy trực tiếp trên máy chủ hoặc từ máy quét trung gian.

### Lưu ý: Ứng dụng chỉ đọc cấu hình và quyền; không chỉnh sửa dữ liệu cũng như không khai thác lỗ hổng.

---

## Các loại lỗ hổng phát hiện

| Mức độ | Kiểm tra |
|--------|----------|
| 🔴 Critical | Tài khoản không mật khẩu, bỏ qua phân quyền, tài khoản ẩn danh |
| 🟠 High | Kết nối không mã hóa, LOAD DATA LOCAL INFILE, quyền global rộng, root đăng nhập từ xa, SSL không cấu hình, phiên bản cũ có CVE |
| 🟡 Medium | Chính sách mật khẩu yếu, host wildcard, general log bật, symbolic links, TLS cũ, replication không SSL |
| 🟢 Low | Mật khẩu không thời hạn, database test tồn tại, password reuse, binlog format STATEMENT, event scheduler |
| ℹ️ Info | Tài khoản cần đổi mật khẩu, audit log chưa bật |

---

## Công nghệ sử dụng

| Thư viện | Vai trò |
|----------|---------|
| `pymysql` | Kết nối và thực thi truy vấn MySQL |
| `ssl` | Thiết lập kết nối SSL/TLS |
| `re` | Parse chuỗi phiên bản MySQL |
| `dataclasses` | Định nghĩa cấu trúc Finding |
| `Flask` | Giao diện web |

---

## Cấu trúc thư mục

```
DBScanner/
├── img/                     # Tài nguyên ảnh
├── static/                  # CSS, JS cho giao diện web
├── templates/               # HTML templates (Flask)
├── app.py                   # Flask app — giao diện web và API
├── scanner.py               # Engine quét chính — toàn bộ logic phát hiện lỗ hổng
├── requirements.txt         # Các dependencies cần thiết
└── README.md
```

---

## Cài đặt

```bash
# Clone repo
git clone https://github.com/ayctyuh/Database-Scanner-Project/DBScanner
cd DBScanner
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux

# Cài đặt dependencies
pip install -r requirements.txt

# Chạy web app
flask --app app run --host 0.0.0.0 --port 5000 --debug
# Hoặc
python app.py --host 0.0.0.0 --port 5000 --debug
```

Truy cập giao diện tại `http://localhost:5000`

- Mở `http://127.0.0.1:5000/` nếu quét ngay trên máy chạy ứng dụng.
- Nếu truy cập từ thiết bị khác, dùng địa chỉ IP thực, ví dụ `http://192.168.1.180:5000/`.

Các biến môi trường `DBSCANNER_HOST`, `DBSCANNER_PORT`, `DBSCANNER_DEBUG=1` có thể dùng để cấu hình nhanh trong môi trường triển khai.
---

## Sử dụng
1. Cung cấp thông tin kết nối (host, port, tài khoản có quyền đọc cấu hình).
2. Nhấn **Bắt đầu quét**. Kết quả trả về gồm:
   - Thanh tóm tắt tổng phát hiện theo mức độ.
   - Danh sách phát hiện dạng accordion; nhấp để xem mô tả, dữ liệu chi tiết và khuyến nghị.
   - Thông tin kết nối và các biến cấu hình quan trọng.
   - Danh sách kiểm tra bị bỏ qua (nếu có) để tiện cấp quyền và quét lại.
3. Xuất/ghi lại báo cáo bằng cách in trang ra PDF nếu cần lưu trữ.
**Kết nối thường:**
```
Host: localhost
Port: 3306
User: root
Password: *your root password*
```

**Kết nối SSL/TLS:**

Tích chọn "Sử dụng SSL" và cung cấp đường dẫn đến các file chứng chỉ:
```
CA Certificate:     /path/to/ca-cert.pem
Client Certificate: /path/to/client-cert.pem
Client Key:         /path/to/client-key.pem
```

Nếu MySQL chưa có SSL, tạo chứng chỉ tự ký:
```bash
# Tạo CA key và certificate
sudo openssl genrsa 2048 | sudo tee ca-key.pem > /dev/null
sudo openssl req -new -x509 -nodes -days 3650 -key ca-key.pem \
  -out ca-cert.pem -subj "/CN=MySQL_CA"

# Tạo Server key và certificate
sudo openssl req -newkey rsa:2048 -days 3650 -nodes \
  -keyout server-key.pem -out server-req.pem -subj "/CN=MySQL_Server"
sudo openssl x509 -req -in server-req.pem -days 3650 \
  -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 -out server-cert.pem
```

---

## Luồng hoạt động

```
Nhập credentials
      ↓
Kết nối MySQL (pymysql)
      ↓
Thu thập metadata (VERSION, CURRENT_USER)
      ↓
Chạy 30+ hàm _check_*()
      ↓
Tổng hợp Finding[] theo mức độ nghiêm trọng
      ↓
Hiển thị báo cáo trên Web UI
```

---

## Kết quả mẫu

```
[CRITICAL] Tài khoản không mật khẩu
  → User 'root'@'%' không có mật khẩu — nguy cơ truy cập trái phép từ xa

[HIGH] Kết nối không mã hóa (SSL disabled)
  → require_secure_transport = OFF
  → Khuyến nghị: Bật SSL/TLS và cấu hình require_secure_transport = ON

[MEDIUM] Chính sách mật khẩu yếu
  → validate_password plugin chưa được kích hoạt
  → Khuyến nghị: INSTALL PLUGIN validate_password SONAME 'validate_password.so'

[LOW] Database test tồn tại
  → Database 'test' mặc định còn tồn tại, bất kỳ user nào cũng có thể truy cập
  → Khuyến nghị: DROP DATABASE test;
```

---

## Yêu cầu

- Python 3.8+
- MySQL 5.7+ hoặc MariaDB 10.3+
- Tài khoản MySQL có quyền đọc `information_schema` và `mysql`

---

## Mở rộng kiểm tra

- Thêm hàm kiểm tra mới trong `scanner.py` và đưa vào danh sách `checks` tại `scan_mysql`. Bạn có thể bổ sung các bước quét chi tiết cho từng schema nếu cần.
- Tách logic kiểm tra theo từng backend (MySQL, PostgreSQL, MSSQL, v.v.) rồi điều chỉnh giao diện để người dùng chọn loại hệ CSDL trước khi quét.
- Tích hợp nhập cấu hình từ file, chạy lịch (cron) hoặc gửi cảnh báo qua webhook.

---
## Giới hạn

- Cần tài khoản có quyền đọc `information_schema` và các bảng hệ thống tương ứng. Thiếu quyền sẽ khiến một số mục bị bỏ qua.
- Không đánh giá được độ mạnh thực tế của mật khẩu (chỉ dựa trên chính sách).
- Không thay thế hoàn toàn cho kiểm thử thâm nhập hoặc audit chuyên sâu; nên kết hợp với các quy trình bảo mật khác.