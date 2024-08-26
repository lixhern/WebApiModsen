using System.Collections.Generic;
using System.Threading.Tasks;

namespace WebApiModsen.WebApiModsen.Core.Interfaces
{
    public interface IRepository<T> where T : class
    {
        Task<IEnumerable<T>> GetAllAsync();
        Task<IEnumerable<T>> GetByPageAsync(int pageNumber, int pageSize);
        Task<T> GetByIdAsync(int id);
        Task InsertAsync(T item);
        Task DeleteByIdAsync(int id);
        Task<int> GetTotalCountAsync();
        Task Delete(T item);
        Task Update(T item);
        Task SaveAsync();
    }
}
