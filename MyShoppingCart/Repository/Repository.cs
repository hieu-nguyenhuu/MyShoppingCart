using Microsoft.EntityFrameworkCore;
using MyShoppingCart.Models;
using NuGet.Packaging.Core;

namespace MyShoppingCart.Repository
{
    public class Repository<T> : IRepository<T> where T : class
    {
        private readonly ApplicationDbContext _dbContext;

        public Repository(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        public async Task AddAsync(T entity)
        {
            await _dbContext.AddAsync(entity);
            await _dbContext.SaveChangesAsync();
        }

        public async Task DeleteAsync(int id)
        {
            var entity = await _dbContext.FindAsync<T>(id);
            if (entity == null)
            {
                return;
            }
            _dbContext.Remove<T>(entity);
            await _dbContext.SaveChangesAsync();
        }

        public async Task<IEnumerable<T>> GetAllAsync()
        {
            return await _dbContext.Set<T>().ToListAsync();
        }

        public async Task<T?> GetByIdAsync(int id)
        {
            return await _dbContext.FindAsync<T>(id);
        }

        public async Task UpdateAsync(T entity)
        {
            _dbContext.Update<T>(entity);
            await _dbContext.SaveChangesAsync();
        }
    }
}
