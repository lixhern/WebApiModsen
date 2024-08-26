using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.AuthController.Refresh
{
    public interface IRefreshUseCase
    {
        Task<LoginResponse> RefreshAsync(string refreshToken);
    }
}
