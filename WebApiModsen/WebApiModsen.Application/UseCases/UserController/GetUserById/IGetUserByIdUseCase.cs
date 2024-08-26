using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetUserById
{
    public interface IGetUserByIdUseCase
    {
        Task<ShowUserInfoModel> GetUserByIdAsync(int userId);
    }
}
