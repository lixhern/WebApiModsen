using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WebApiModsen.WebApiModsen.Infrastructure.Repositories;
using Xunit;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Options;
using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Core.Enum;
using WebApiModsen.WebApiModsen.Infrastructure.Data;

namespace WebApiModsen.Test.Repositories
{
    public class UserEventRepositoryTests
    {
        private async Task SeedDatabaseAsync(ApplicationDbContext context)
        {
            context.Users.AddRange(new List<User>
            {
                new User
                {
                    Name = "Mark",
                    LastName = "Gol",
                    Email = "mark.gol@example.com",
                    Password = "password123",
                    DateOfBirth = new DateTime(1990, 1, 1),
                    DateOfRegistrationOnEvent = new DateTime(2024, 8, 1),
                },
                new User
                {
                    Name = "Vickor",
                    LastName = "Pypkin",
                    Email = "vickor.pypkin@example.com",
                    Password = "password456",
                    DateOfBirth = new DateTime(1992, 2, 2),
                    DateOfRegistrationOnEvent = null,
                }
            });

            context.Events.AddRange(new List<Event>
            {
                new Event
            {
                Title = "Event 1",
                Description = "Description for Event 1",
                DateOfEvent = DateTime.Now.AddDays(10).Date,
                Location = "Location 1",
                CategoryOfEvent = EventCategory.Conference,
                MaximumOfMember = 100,
                CurrentNumberOfMember = 50,
                ImageUrl = "/images/event1.jpg",
                ImagePath = "/path/event1.jpg"
            },
            new Event
            {

                Title = "Event 2",
                Description = "Description for Event 2",
                DateOfEvent = DateTime.Now.AddDays(20).Date,
                Location = "Location 2",
                CategoryOfEvent = EventCategory.Workshop,
                MaximumOfMember = 50,
                CurrentNumberOfMember = 20,
                ImageUrl = "/images/event2.jpg",
                ImagePath = "/path/event2.jpg"
            }
            });

            context.UserEvents.AddRange(new List<UserEvent>
            {
                new UserEvent
                {
                    UserId = 1,
                    EventId = 1,
                    RegistrationDate = DateTime.Now.AddDays(-1).Date,
                },
                new UserEvent
                {
                     UserId = 1,
                    EventId = 2,
                    RegistrationDate = DateTime.Now.AddDays(-2)
                },
                new UserEvent
                {
                     UserId = 2,
                    EventId = 2,
                    RegistrationDate = DateTime.Now.AddDays(-3)
                }
            });

            await context.SaveChangesAsync();
        }
        private async Task<ApplicationDbContext> GetDatabaseContextAsync()
        {
            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;

            var context = new ApplicationDbContext(options);
            await SeedDatabaseAsync(context);
            return context;
        }

        [Fact]
        public async Task AlreadyRegistredAsync_ReturnTrueOrFalse()
        {
            using(var context = await GetDatabaseContextAsync())
            {
                var repository = new UserEventRepository(context);

                bool isRegistered = await repository.AlreadyRegistredAsync(1, 1);
                bool isNotRegistered = await repository.AlreadyRegistredAsync(2, 1);

                Assert.True(isRegistered);
                Assert.False(isNotRegistered);

            }

        }

        [Fact]
        public async Task GetByUserIdAndEventIdAsync_ReturnUserEventItem()
        {
            using (var context = await GetDatabaseContextAsync())
            {
                var repository = new UserEventRepository(context);
                var userEvent = await repository.GetByUserIdAndEventIdAsync(1, 1);
                Assert.NotNull(userEvent);
                Assert.Equal(DateTime.Now.AddDays(-1).Date, userEvent.RegistrationDate);
                Assert.Equal(1, userEvent.UserId);
                Assert.Equal(1, userEvent.EventId);
            }
        }
    }
}
