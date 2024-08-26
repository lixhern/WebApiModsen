using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetUserEvents
{
    public interface IGetUserEventsUseCase
    {
        Task<IEnumerable<EventModel>> GetUserEventsAsync(int userId);
    }
}
