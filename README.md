# Auth API - JWT Authentication (.NET 8)
## Công việc đã hoàn thành
+ **Cấu hình hệ thống:** Khởi tạo Web API với .NET 8, kết nối SQL Server thông qua Entity Framework Core (Code-First).
+ **Bảo mật dữ liệu:** Thực hiện băm (Hash) mật khẩu người dùng trước khi lưu xuống cơ sở dữ liệu.
+ **Xác thực JWT:** Cấu hình và cấp phát Bearer Token khi đăng nhập thành công để bảo vệ các endpoint.
+ **Tối ưu Input Validation:** Ứng dụng `Data Annotations` (Required, MinLength, RegularExpression) để chặn dữ liệu rác ngay từ đầu vào.
## Các Endpoint chính (Test trực tiếp trên Swagger)
1. `POST /api/Auth/register`: Đăng ký tài khoản (Yêu cầu mật khẩu mạnh, độ dài phù hợp).
2. `POST /api/Auth/login`: Đăng nhập và nhận chuỗi JWT.
3. `GET /api/Auth/...` *(Các API cần bảo vệ)*: Yêu cầu đính kèm Bearer Token hợp lệ trên Header để truy cập.
