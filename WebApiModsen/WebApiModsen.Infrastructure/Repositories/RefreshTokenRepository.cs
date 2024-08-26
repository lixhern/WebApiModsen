using Microsoft.EntityFrameworkCore;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Infrastructure.Data;

namespace WebApiModsen.WebApiModsen.Infrastructure.Repositories
{
    public class RefreshTokenRepository : Repository<RefreshToken>, IRefreshTokenRepository
    {
        private readonly ApplicationDbContext _context;

        public RefreshTokenRepository(ApplicationDbContext context) : base(context)
        {
            _context = context;
        }

        public async Task<RefreshToken> GetRefreshTokenAsync(string token)
        {
            return await _context.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token.Equals(token) && !rt.IsRevoked);
        }
    }
}
