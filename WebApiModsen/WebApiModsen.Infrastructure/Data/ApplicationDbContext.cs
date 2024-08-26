using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Infrastructure.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
            Database.EnsureCreated();
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Event> Events { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<UserEvent> UserEvents { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);
        }
    }
}

