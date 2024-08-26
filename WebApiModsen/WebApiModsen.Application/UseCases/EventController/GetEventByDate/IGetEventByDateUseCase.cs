using System.Collections;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByDate
{
    public interface IGetEventByDateUseCase
    {
        Task<IEnumerable<EventModel>> GetEventsByDateAsync(DateTime date);
    }
}
