using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByLocation
{
    public interface IGetEventByLocationUseCase
    {
        Task<IEnumerable<EventModel>> GetEventByLocationAsync(string location);
    }
}
