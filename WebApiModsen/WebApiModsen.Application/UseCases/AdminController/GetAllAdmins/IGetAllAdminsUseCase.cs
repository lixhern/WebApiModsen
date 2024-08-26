using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.AdminController.GetAllAdmins
{
    public interface IGetAllAdminsUseCase
    {
        Task<IEnumerable<ShowUserInfoModel>> GetAllAdminsAsync();
    }
}
