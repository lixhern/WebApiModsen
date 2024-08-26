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
    public class RepositoryTest
    {
        private async Task SeedDatabaseAsync(ApplicationDbContext context)
        {
            context.Events.AddRange(new List<Event>
                {
                new Event
                {
                    Id = 1,
                    Title = "Event 1",
                    Description = "Description for Event 1",
                    DateOfEvent = DateTime.Now.AddDays(10),
                    Location = "Location 1",
                    CategoryOfEvent = EventCategory.Conference,
                    MaximumOfMember = 100,
                    CurrentNumberOfMember = 50,
                    ImageUrl = "/images/event1.jpg",
                    ImagePath = "/path/event1.jpg"
                },
                new Event
                {
                    Id = 2,
                    Title = "Event 2",
                    Description = "Description for Event 2",
                    DateOfEvent = DateTime.Now.AddDays(20),
                    Location = "Location 2",
                    CategoryOfEvent = EventCategory.Workshop,
                    MaximumOfMember = 50,
                    CurrentNumberOfMember = 20,
                    ImageUrl = "/images/event2.jpg",
                    ImagePath = "/path/event2.jpg"
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
        public async Task GetAllAsync_ReturnsAllItems()
        {
            using (var context = await GetDatabaseContextAsync())
            {
                var repository = new EventRepository(context);

                // Act
                var events = await repository.GetAllAsync();
                var eventsCount = await repository.GetTotalCountAsync();


                // Assert
                Assert.Equal(eventsCount, events.Count());
                Assert.Contains(events, e => e.Title == "Event 1");
                Assert.Contains(events, e => e.Title == "Event 2");
            }
        }

        [Fact]
        public async Task GetByPageAsync_ReturnsCorrectPageOfItems()
        {
            // Act
            using (var context = await GetDatabaseContextAsync())
            {
                var repository = new Repository<Event>(context);
                var pageNumber = 2;
                var pageSize = 1;
                var events = await repository.GetByPageAsync(pageNumber, pageSize);

                // Assert
                Assert.NotNull(events);
                Assert.Equal(1, events.Count());
                Assert.Contains(events, e => e.Id == 2);
            }
        }

        [Fact]
        public async Task GetByIdAsync_ReturnsItemById()
        {
            using (var context = await GetDatabaseContextAsync())
            {
                var repository = new EventRepository(context);

                // Act
                var @event = await repository.GetByIdAsync(1);

                // Assert
                Assert.NotNull(@event);
                Assert.Equal("Event 1", @event.Title);
            }
        }

        [Fact]
        public async Task InsertAsync_AddsNewItem()
        {
            using (var context = await GetDatabaseContextAsync())
            {
                var repository = new EventRepository(context);
                var newEvent = new Event
                {
                    Title = "Event 3",
                    Description = "Description for Event 3",
                    DateOfEvent = DateTime.Now.AddDays(10),
                    Location = "Location 3",
                    CategoryOfEvent = EventCategory.Conference,
                    MaximumOfMember = 100,
                    CurrentNumberOfMember = 50,
                    ImageUrl = "/images/event1.jpg",
                    ImagePath = "/path/event1.jpg"
                };
                await repository.InsertAsync(newEvent);
                await repository.SaveAsync();

                var @event = await repository.GetAllAsync();
                Assert.NotEmpty(@event);
                var addedEventInDb = @event.FirstOrDefault(e => e.Title == "Event 3");
                Assert.NotNull(addedEventInDb);
                Assert.Equal("Event 3", addedEventInDb.Title);
                Assert.Equal("Description for Event 3", addedEventInDb.Description);
                Assert.Equal("Location 3", addedEventInDb.Location);
            }
        }

        [Fact]
        public async Task DeleteByIdAsync_RemovesItem()
        {
            using (var context = await GetDatabaseContextAsync())
            {
                var repository = new EventRepository(context);

                // Act
                await repository.DeleteByIdAsync(2);
                await repository.SaveAsync();
                // Assert
                var @event = await repository.GetByIdAsync(2);
                Assert.Null(@event);
            }
        }

        [Fact]
        public async Task GetTotalCountAsync_GetTotalItemsCount()
        {
            using (var context = await GetDatabaseContextAsync())
            {
                var repository = new EventRepository(context);

                // Act
                var events = await repository.GetTotalCountAsync();

                // Assert
                Assert.Equal(2, events);

            }
        }

        [Fact]
        public async Task Delete_RemoveItem()
        {
            
            using (var context = await GetDatabaseContextAsync())
            {
                var repository = new EventRepository(context);
                var @event = await repository.GetByIdAsync(2);
                // Act
                await repository.Delete(@event);
                await repository.SaveAsync();
                var @event1 = await repository.GetByIdAsync(2);
                Assert.Null(@event1);
            }
        }

        [Fact]
        public async Task Update_UpdateItemData()
        {
            using (var context = await GetDatabaseContextAsync())
            {
                var repository = new EventRepository(context);
                var @event = await repository.GetByIdAsync(1);
                @event.Title = "Change";
                await repository.Update(@event);
                await context.SaveChangesAsync();
                var @event1 = await repository.GetByIdAsync(1);
                Assert.Equal("Change", @event1.Title);
            }
        }
    }
}
