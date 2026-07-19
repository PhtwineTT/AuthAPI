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
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        public AuthService(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        public async Task<string> RegisterAsync(RegisterDto request)
        {
            bool checkUpper = await _context.Users.AnyAsync(u => EF.Functions.Collate(u.Username, "SQL_Latin1_General_CP1_CS_AS") == request.Username);
            if (checkUpper) return "Tên tài khoản đã tồn tại";

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

        public async Task<(TokenDto? tokens, string error)> LoginAsync(LoginDto request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => EF.Functions.Collate(u.Username, "SQL_Latin1_General_CP1_CS_AS") == request.Username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.Password))
            {
                return (null, "Sai tài khoản hoặc mật khẩu");
            }

            var token = CreateToken(user);
            var refreshToken = CreateRefreshToken();

            user.RefreshToken = refreshToken;
            user.ExpiryTime = DateTime.Now.AddDays(7);
            await _context.SaveChangesAsync();

            return (new TokenDto { AccessToken = token, RefreshToken = refreshToken }, string.Empty);
        }
        public async Task<(TokenDto? tokens, string error)> RefreshTokenAsync(TokenDto request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.RefreshToken == request.RefreshToken);
            if (user == null) return (null, "Token không tồn tại.");

            if (user.ExpiryTime < DateTime.Now) return (null, "Token đã hết hạn.");

            var newAccessToken = CreateToken(user);
            var newRefreshToken = CreateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.ExpiryTime = DateTime.Now.AddDays(7);
            await _context.SaveChangesAsync();

            return (new TokenDto { AccessToken = newAccessToken, RefreshToken = newRefreshToken }, string.Empty);
        }
        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role)
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtConfig:Secret"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: _configuration["JwtConfig:Issuer"],
                audience: _configuration["JwtConfig:Audience"],
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        private string CreateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
    }
}