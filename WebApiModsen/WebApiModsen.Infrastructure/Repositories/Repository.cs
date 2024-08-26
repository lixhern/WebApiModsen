using Microsoft.EntityFrameworkCore;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Infrastructure.Data;

namespace WebApiModsen.WebApiModsen.Infrastructure.Repositories
{
    public class Repository<T> : IRepository<T> where T : class
    {
        private readonly ApplicationDbContext _context;
        public Repository(ApplicationDbContext context)
        {
            _context = context;
        }

        public virtual async Task<IEnumerable<T>> GetAllAsync()
        {
            return await _context.Set<T>().ToListAsync();
        }

        public async Task<IEnumerable<T>> GetByPageAsync(int pageNumber, int pageSize)
        {
            return await _context.Set<T>()
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();
        }

        public async Task<T> GetByIdAsync(int id)
        {
            return await _context.Set<T>().FindAsync(id);
        }

        public async Task InsertAsync(T item)
        {
            await _context.Set<T>().AddAsync(item);
        }

        public async Task DeleteByIdAsync(int id)
        {
            T item = await _context.Set<T>().FindAsync(id);
            Delete(item);
        }

        public async Task<int> GetTotalCountAsync()
        {
            return await _context.Events.CountAsync();
        }

        public async Task Delete(T item)
        {
            _context.Set<T>().Remove(item);
        }

        public async Task Update(T item)
        {
            _context.Entry(item).State = EntityState.Modified;
        }

        public async Task SaveAsync()
        {
            await _context.SaveChangesAsync();
        }
    }
}
