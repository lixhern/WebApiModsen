using System.Threading.Tasks;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Core.Interfaces
{
    public interface IUserEventRepository : IRepository<UserEvent>
    {
        Task<bool> AlreadyRegistredAsync(int userId, int eventId);
        Task<UserEvent> GetByUserIdAndEventIdAsync(int userId, int eventId);
    }
}
