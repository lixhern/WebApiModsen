using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using WebApiModsen.WebApiModsen.Core.Enum;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Core.Interfaces
{
    public interface IEventRepository : IRepository<Event>
    {
        Task<IEnumerable<Event>> GetEventByTitleAsync(string title);
        Task<IEnumerable<Event>> GetEventByCategoryAsync(EventCategory category);
        Task<IEnumerable<Event>> GetEventByDateAsync(DateTime date);
        Task<IEnumerable<Event>> GetEventByLocationAsync(string location);
        Task<IEnumerable<Event>> GetUserEventsAsync(int userId);
    }
}
