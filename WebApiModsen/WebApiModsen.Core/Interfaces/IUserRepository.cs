using System.Collections.Generic;
using System.Threading.Tasks;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Core.Interfaces
{
    public interface IUserRepository : IRepository<User>
    {
        Task<IEnumerable<User>> GetAllAdminsAsync();
        Task<bool> UserEcistsByEmailAsync(string email);
        Task<User> GetUserForLoginAsync(string email, string password);
        Task<IEnumerable<User>> GetParticipantsOfEventAsync(int eventId);
    }
}
