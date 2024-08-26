using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByCategory
{
    public interface IGetEventByCategoryUseCase
    {
        Task<IEnumerable<EventModel>> GetEventsByCategoryAsync(int categoryId);
    }
}
