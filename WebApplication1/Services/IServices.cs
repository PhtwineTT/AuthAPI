using AuthAPI.DTO;
using AuthAPI.Models;
namespace AuthAPI.Services
{
    public interface IServices
    {
        Task<string> RegisterAsync(RegisterDto request);
        Task<(TokenDto? tokens, string error)> LoginAsync(LoginDto request);
        Task<(TokenDto? tokens, string error)> RefreshTokenAsync(TokenDto request);
    }
}
