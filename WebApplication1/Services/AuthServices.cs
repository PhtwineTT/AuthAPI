using AuthAPI.DATA;
using AuthAPI.DTO;
using AuthAPI.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
namespace AuthAPI.Services
{
    public class AuthService : IServices
    {
        // Khởi tạo bằng Constructor Injection để đảm bảo lấy được dữ liệu từ database
        private readonly AppDbContext _context; // Tìm user trong database và lưu user mới
        private readonly IConfiguration _configuration; // Đọc dữ liệu từ file json 
        public AuthService(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        // Kiểm tra và trước khi lưu tài khoản mới vào database
        public async Task<string> RegisterAsync(RegisterDto request)
        {
            // Ép kiểu Username để phân biệt chữ hoa chữ thường
            bool checkUpper = await _context.Users.AnyAsync(u => EF.Functions.Collate(u.Username, "SQL_Latin1_General_CP1_CS_AS") == request.Username);
            if (checkUpper) return "Tên tài khoản đã tồn tại";
            // Dùng BCrypt đẻ hash mật khẩu và sinh ra 1 chuỗi kí tự ngẫu nhiên
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);
            var user = new User()
            {
                Username = request.Username,
                Password = passwordHash
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return "Success";
        }

        // Đăng nhập và trả về token
        public async Task<(TokenDto? tokens, string error)> LoginAsync(LoginDto request)
        {
            // Tìm thông tin trong database với EF để phân biệt chữ hoa và thường
            var user = await _context.Users.FirstOrDefaultAsync(u => EF.Functions.Collate(u.Username, "SQL_Latin1_General_CP1_CS_AS") == request.Username);
            // Dùng BCrypt để giải mã lại mật khẩu rồi đối chiếu
            if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.Password))
            {
                return (null, "Sai tài khoản hoặc mật khẩu");
            }
            var token = CreateToken(user);
            var refreshToken = CreateRefreshToken();
            user.RefreshToken = refreshToken;
            user.ExpiryTime = DateTime.Now.AddDays(7); // Gắn RefreshToken là 7 ngày tránh login lại nhiều lần liên tục
            await _context.SaveChangesAsync();
            return (new TokenDto { AccessToken = token, RefreshToken = refreshToken }, string.Empty);
        }

        // Cấp Refresh Token
        public async Task<(TokenDto? tokens, string error)> RefreshTokenAsync(TokenDto request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.RefreshToken == request.RefreshToken);
            if (user == null) return (null, "Token không tồn tại.");
            // Kiểm tra thời hạn
            if (user.ExpiryTime < DateTime.Now) return (null, "Token đã hết hạn.");
            //Cấp lại hoàn toàn một cặp thẻ mới(Cả Access lẫn Refresh mới) và xóa Refresh cũ.
            var newAccessToken = CreateToken(user);
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.ExpiryTime = DateTime.Now.AddDays(7);
            await _context.SaveChangesAsync();
            return (new TokenDto { AccessToken = newAccessToken, RefreshToken = newRefreshToken }, string.Empty);
        }

        // Tạo token
        private string CreateToken(User user)
        {
            // Payload của token
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role)
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtConfig:Secret"]!));
            // Dùng HMAC-SHA256 tạo signature, khi thay đổi payload sẽ làm sai lệch signature
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: _configuration["JwtConfig:Issuer"],
                audience: _configuration["JwtConfig:Audience"],
                claims: claims,
                expires: DateTime.Now.AddDays(1), // Access token để 1 ngày để đảm bảo bảo mật
                signingCredentials: creds
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string CreateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var random = RandomNumberGenerator.Create()) // RandomNumberGenerator để tạo các số ngẫu nhiên từ tín hiệu máy chủ
            {
                random.GetBytes(randomNumber);
                // Biến ngược mảng byte thành chuỗi base64 để truyền được qua HTTP
                return Convert.ToBase64String(randomNumber);
            }
        }
    }
}