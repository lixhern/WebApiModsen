using Microsoft.EntityFrameworkCore;
using WebApiModsen.WebApiModsen.Core.Enum;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Infrastructure.Data;

namespace WebApiModsen.WebApiModsen.Infrastructure.Repositories
{
    public class EventRepository : Repository<Event>, IEventRepository
    {
        private readonly ApplicationDbContext _context;

        public EventRepository(ApplicationDbContext context) : base(context)
        {
            _context = context;
        }

        public async Task<IEnumerable<Event>> GetEventByTitleAsync(string title)
        {
            return await _context.Events
                .Where(e => e.Title.ToLower().Equals(title.ToLower()))
                .ToListAsync();
        }
        public async Task<IEnumerable<Event>> GetEventByCategoryAsync(EventCategory category)
        {
            return await _context.Events
                .Where(e => e.CategoryOfEvent == category)
                .ToListAsync();
        }

        public async Task<IEnumerable<Event>> GetEventByDateAsync(DateTime date)
        {
            return await _context.Events
                .Where(e => e.DateOfEvent.Date == date.Date)
                .ToListAsync();
        }

        public async Task<IEnumerable<Event>> GetEventByLocationAsync(string location)
        {
            return await _context.Events
                .Where(e => e.Location.ToLower().Equals(location.ToLower()))
                .ToListAsync();
        }

        public async Task<IEnumerable<Event>> GetUserEventsAsync(int userId)
        {
            return await _context.Users
                .Where(u => u.Id == userId)
                .SelectMany(u => u.UserEvents)
                .Select(ue => ue.Event)
                .ToListAsync();

        }

    }
}
