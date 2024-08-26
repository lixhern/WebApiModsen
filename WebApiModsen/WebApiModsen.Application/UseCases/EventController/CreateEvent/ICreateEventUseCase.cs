using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.CreateEvent
{
    public interface ICreateEventUseCase
    {
        Task CreateEventAsync(CreateEventModel createEvent);
    }
}
