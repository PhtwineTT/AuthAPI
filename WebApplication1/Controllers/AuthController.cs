using Microsoft.AspNetCore.Mvc;
using AuthAPI.DATA;
using AuthAPI.Models;
using AuthAPI.DTO;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Authorization;
namespace AuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        public AuthController(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }
        [HttpPost("register")]
        public IActionResult CreateUser(UserDto request)
        {
            // Loại khoảng trắng
            if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            {
                return BadRequest("Tên tài khoản và mật khẩu không được để trống");
            }
            // Kiểm tra và lưu vào Database
            bool checkUpper = _context.Users.Any(u => EF.Functions.Collate(u.Username, "SQL_Latin1_General_CP1_CS_AS") == request.Username);
            if (checkUpper)
            {
                return BadRequest("Tên tài khoản đã tồn tại");
            }
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);
            var user = new User()
            {
                Username = request.Username,
                Password = passwordHash
            };
            _context.Users.Add(user);
            _context.SaveChanges();
            return Ok("Đăng ký thành công");
        }
        [HttpPost("login")]
        public IActionResult LogIn(UserDto request)
        {
            // Loại khoảng trắng
            if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            {
                return BadRequest("Hãy nhập đầy đủ tên tài khoản và mật khẩu");
            }
            // Đối chiếu trong Database
            var user = _context.Users.FirstOrDefault(u => EF.Functions.Collate(u.Username, "SQL_Latin1_General_CP1_CS_AS") == request.Username);
            if (user == null)
            {
                return BadRequest("Sai tên tài khoản hoặc mật khẩu");
            }

            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.Password))
            {
                return BadRequest("Sai tài khoản hoặc mật khẩu");
            }
            // Tạo token
            string token = CreateToken(user);
            // In token ra màn hình để copy dán vào Swagger
            return Ok(new
            {
                Message = "Đăng nhập thành công",
                Token = token
            });
        }
        // Hàm tạo token
        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
            );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
        // Test cấu hình
        [HttpGet("profile")]
        [Authorize]
        public IActionResult Profile()
        {
            return Ok("Xác thực thành công");
        }
    }
}