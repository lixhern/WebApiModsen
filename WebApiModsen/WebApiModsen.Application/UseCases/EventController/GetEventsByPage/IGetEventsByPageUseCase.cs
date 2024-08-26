using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventsByPage
{
    public interface IGetEventsByPageUseCase
    {
        Task<ItemPageResult<EventModel>> GetEventsByPageAsync(int pageNumber, int pageSize);
    }
}
