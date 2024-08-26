
namespace WebApiModsen.WebApiModsen.Core.Interfaces
{
    public interface IUnitOfWork : IDisposable
    {
        IUserRepository UserRepository { get; }
        IRefreshTokenRepository RefreshTokenRepository { get; }
        IEventRepository EventRepository { get; }
        IUserEventRepository UserEventRepository { get; }
        Task SaveAsync();
    }
}
