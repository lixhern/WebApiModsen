using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Infrastructure.Repositories;

namespace WebApiModsen.WebApiModsen.Infrastructure.Data
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly ApplicationDbContext _context;
        private IUserRepository _userRepository;
        private IRefreshTokenRepository _refreshTokenRepository;
        private IEventRepository _eventRepository;
        private IUserEventRepository _userEventRepository;

        public UnitOfWork(ApplicationDbContext context)
        {
            _context = context;
        }

        public IUserRepository UserRepository
        {
            get
            {
                if (_userRepository == null)
                {
                    _userRepository = new UserRepository(_context);

                }
                return _userRepository;
            }
        }

        public IRefreshTokenRepository RefreshTokenRepository
        {
            get
            {
                if (_refreshTokenRepository == null)
                {
                    _refreshTokenRepository = new RefreshTokenRepository(_context);

                }
                return _refreshTokenRepository;
            }
        }

        public IEventRepository EventRepository
        {
            get
            {
                if (_eventRepository == null)
                {
                    _eventRepository = new EventRepository(_context);

                }
                return _eventRepository;
            }
        }

        public IUserEventRepository UserEventRepository
        {
            get
            {
                if (_userEventRepository == null)
                {
                    _userEventRepository = new UserEventRepository(_context);

                }
                return _userEventRepository;
            }
        }

        public async Task SaveAsync()
        {
            await _context.SaveChangesAsync();
        }

        private bool _disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _context.Dispose();
                }
            }
            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }


    }
}
