using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetUsersByPage
{
    public interface IGetUsersByPageUseCase
    {
        Task<ItemPageResult<ShowUserInfoModel>> GetUsersByPageAsync(int pageNumber, int pageSize);
    }
}
