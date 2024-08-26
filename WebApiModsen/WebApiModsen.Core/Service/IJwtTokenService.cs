using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Core.Service
{
    public interface IJwtTokenService
    {
        string GenerateJwtToken(User user);
        RefreshToken GenerateRefreshToken(int userId);
    }
}
