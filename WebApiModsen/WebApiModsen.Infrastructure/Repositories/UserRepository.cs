using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Infrastructure.Data;

namespace WebApiModsen.WebApiModsen.Infrastructure.Repositories
{
    public class UserRepository : Repository<User>, IUserRepository
    {
        private readonly ApplicationDbContext _context;

        public UserRepository(ApplicationDbContext context) : base(context)
        {
            _context = context;
        }

        public async Task<IEnumerable<User>> GetAllAdminsAsync()
        {
            return await _context.Users
                .Where(u => u.Role.Equals("Admin"))
                .ToListAsync();
        }
        public async Task<bool> UserEcistsByEmailAsync(string email)
        {
            return await _context.Users.AnyAsync(u => u.Email == email);
        }

        public async Task<User> GetUserForLoginAsync(string email, string password)
        {
            return await _context.Users.FirstOrDefaultAsync(u => u.Email.Equals(email) && u.Password.Equals(password));
        }

        public async Task<IEnumerable<User>> GetParticipantsOfEventAsync(int eventId)
        {
            return await _context.Events
                .Where(e => e.Id == eventId)
                .SelectMany(e => e.UserEvents)
                .Select(ue => ue.User)
                .ToListAsync();
        }


    }
}
