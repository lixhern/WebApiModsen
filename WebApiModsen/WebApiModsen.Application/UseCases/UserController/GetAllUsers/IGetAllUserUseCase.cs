using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetAllUsers
{
    public interface IGetAllUserUseCase
    {
        Task<IEnumerable<ShowUserInfoModel>> GetAllUsersAsync();
    }
}
