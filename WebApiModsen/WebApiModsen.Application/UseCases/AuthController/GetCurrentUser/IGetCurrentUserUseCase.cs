using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.AuthController.GetCurrentUser
{
    public interface IGetCurrentUserUseCase
    {
        Task<ShowUserInfoModel> GetCurrentUserAsync(int userId);
    }
}
