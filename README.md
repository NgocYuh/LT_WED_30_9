# Bài tập JWT - Spring Boot 3 / Spring Security 6

Ứng dụng thực hiện đầy đủ luồng trong bài giảng `04_JWT.pdf`: đăng ký, đăng nhập nhận JWT, filter đọc Bearer token, xem hồ sơ, liệt kê người dùng và giao diện AJAX. Phiên bản hiện tại dùng **Nimbus JOSE + JWT 9.37.3**; phiên bản JJWT 0.12.6 vẫn xem được ở commit giai đoạn 1.

## Yêu cầu

- JDK 17 trở lên và Maven 3.9+
- MySQL 8+
- Secret HS256 là chuỗi Base64 giải mã được tối thiểu 32 byte

Sao chép các tên biến từ `.env.example`, nhưng không commit file `.env` hay giá trị thật. Spring Boot đọc biến môi trường của hệ điều hành, không tự đọc file `.env`.

PowerShell mẫu:

```powershell
$env:DB_URL = 'jdbc:mysql://localhost:3306/jwt_demo?createDatabaseIfNotExist=true&serverTimezone=UTC&allowPublicKeyRetrieval=true&useSSL=false'
$env:DB_USERNAME = 'root'
$env:DB_PASSWORD = 'your-password'
$env:JWT_SECRET = [Convert]::ToBase64String((1..48 | ForEach-Object { Get-Random -Maximum 256 }))
$env:JWT_EXPIRATION_MS = '3600000'
mvn spring-boot:run
```

`JWT_EXPIRATION_MS` và trường `expiresIn` trong response đều tính bằng **mili giây**. Giá trị mặc định là `3600000` (1 giờ). Ứng dụng chạy tại `http://localhost:8005`.

## Gọi API

Đăng ký:

```bash
curl -X POST http://localhost:8005/auth/signup -H "Content-Type: application/json" -d '{"email":"student@example.com","password":"Password123!","fullName":"JWT Student"}'
```

Đăng nhập và lấy `token`:

```bash
curl -X POST http://localhost:8005/auth/login -H "Content-Type: application/json" -d '{"email":"student@example.com","password":"Password123!"}'
```

Gọi endpoint được bảo vệ:

```bash
curl http://localhost:8005/users/me -H "Authorization: Bearer <token>"
```

`GET /users` dành cho vai trò `ADMIN`; tài khoản đăng ký công khai luôn có vai trò `USER`. Để thử trong môi trường học tập, đổi vai trò trực tiếp trong MySQL rồi đăng nhập lại:

```sql
UPDATE users SET role = 'ADMIN' WHERE email = 'student@example.com';
```

API không bao giờ trả password/hash. Thiếu token, token sai định dạng/chữ ký hoặc hết hạn trả `401`; tài khoản `USER` gọi `/users` trả `403`; sai thông tin đăng nhập trả `401`.

## Giao diện AJAX

1. Tạo tài khoản qua `POST /auth/signup`.
2. Mở `http://localhost:8005/login`.
3. Đăng nhập; trình duyệt lưu token trong `sessionStorage` và chuyển tới `/user/profile`.
4. Trang profile gọi `/users/me` bằng Bearer token. Nút đăng xuất xóa token.

## Build và kiểm thử

```bash
mvn clean test
mvn clean package
```

Test tích hợp dùng H2 riêng, không chạm vào MySQL, và kiểm tra: đăng ký -> đăng nhập -> `/users/me`, quyền `/users`, không rò rỉ password/hash, sai mật khẩu, thiếu token, token lỗi, sai chữ ký và token hết hạn.

Nimbus chỉ chấp nhận đúng thuật toán `HS256`, xác minh chữ ký trước, rồi mới kiểm tra `exp` và đọc `sub`. API, Bearer header, claims và thời hạn giữ nguyên so với phiên bản JJWT.
