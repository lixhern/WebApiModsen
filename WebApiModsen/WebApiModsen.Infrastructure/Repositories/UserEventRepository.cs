using Microsoft.EntityFrameworkCore;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Infrastructure.Data;

namespace WebApiModsen.WebApiModsen.Infrastructure.Repositories
{
    public class UserEventRepository : Repository<UserEvent>, IUserEventRepository
    {
        private readonly ApplicationDbContext _context;

        public UserEventRepository(ApplicationDbContext context) : base(context)
        {
            _context = context;
        }

        public async Task<bool> AlreadyRegistredAsync(int userId, int eventid)
        {
            return await _context.UserEvents.AnyAsync(ue => ue.UserId == userId && ue.EventId == eventid);
        }

        public async Task<UserEvent> GetByUserIdAndEventIdAsync(int userId, int eventId)
        {
            return await _context.UserEvents.FirstOrDefaultAsync(ue => ue.UserId == userId && ue.EventId == eventId);
        }
    }
}
