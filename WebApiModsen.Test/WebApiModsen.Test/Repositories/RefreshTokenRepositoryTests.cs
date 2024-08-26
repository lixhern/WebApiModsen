using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Infrastructure.Repositories;
using WebApiModsen.WebApiModsen.Core.Enum;
using Xunit;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Options;
using WebApiModsen.WebApiModsen.Infrastructure.Data;

namespace WebApiModsen.Test.Repositories
{
    public class RefreshTokenRepositoryTests
    {
        private DbContextOptions<ApplicationDbContext> CreateNewContextOptions()
        {
            return new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;
        }

        [Fact]
        public async Task GetRefreshTokenAsync_ReturnRefreshToken()
        {
            var options = CreateNewContextOptions();
            using(var context = new ApplicationDbContext(options))
            {
                context.RefreshTokens.Add(new RefreshToken
                {
                    Id = 1,
                    Token = "sampleToken",
                    ExpiryDate = DateTime.UtcNow.AddDays(7),
                    IsRevoked = false,
                    UserId = 1,
                    User = new User
                    {
                        Name = "Mark",
                        LastName = "Gol",
                        Email = "mark.gol@example.com",
                        Password = "password123",
                        DateOfBirth = new DateTime(1990, 1, 1),
                        DateOfRegistrationOnEvent = new DateTime(2024, 8, 1),
                    }
                });
                await context.SaveChangesAsync();
            }
            using(var context = new ApplicationDbContext(options))
            {
                var repository = new RefreshTokenRepository(context);

                var token = await repository.GetRefreshTokenAsync("sampleToken");

                Assert.NotNull(token);
                Assert.Equal(1, token.Id);
                Assert.Equal(1, token.UserId);
            
            }
        }
    }
}
