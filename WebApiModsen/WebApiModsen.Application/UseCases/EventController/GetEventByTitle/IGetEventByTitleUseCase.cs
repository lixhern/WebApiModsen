using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByTitle
{
    public interface IGetEventByTitleUseCase
    {
        Task<IEnumerable<EventModel>> GetEventByTitleAsync(string title);
    }
}
