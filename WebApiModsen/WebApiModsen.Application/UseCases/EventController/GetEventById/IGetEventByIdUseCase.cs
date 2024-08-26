using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventById
{
    public interface IGetEventByIdUseCase
    {
        Task<EventModel> GetEventByIdAsync(int id);
    }
}
