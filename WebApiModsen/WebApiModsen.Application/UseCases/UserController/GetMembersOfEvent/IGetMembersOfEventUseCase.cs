using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetMembersOfEvent
{
    public interface IGetMembersOfEventUseCase
    {
        Task<IEnumerable<ShowUserInfoModel>> GetMembersOfEventAsync(int eventId);
    }
}
