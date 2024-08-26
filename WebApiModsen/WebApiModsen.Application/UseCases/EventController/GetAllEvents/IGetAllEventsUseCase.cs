using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetAllEvents
{
    public interface IGetAllEventsUseCase
    {
        Task<IEnumerable<EventModel>> GetAllEventsAsync();
    }
}
