using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using FluentValidation;

using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.ChangeEventInfo;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.CreateEvent;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.DeleteEvent;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetAllEvents;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByCategory;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByDate;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventById;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByLocation;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByTitle;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventsByPage;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetUserEvents;

namespace WebApiModsen.WebApiModsen.Web.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    public class EventController : ControllerBase
    {
        private readonly AbstractValidator<CreateEventModel> _eventModelValidator;
        private readonly ICreateEventUseCase _createEventUseCase;
        private readonly IChangeEventInfoUseCase _changeEventInfoUseCase;
        private readonly IGetAllEventsUseCase _getAllEventsUseCase;
        private readonly IGetEventsByPageUseCase _getEventsByPageUseCase;
        private readonly IGetEventByIdUseCase _getEventByIdUseCase;
        private readonly IGetEventByTitleUseCase _getEventByTitleUseCase;
        private readonly IGetEventByLocationUseCase _getEventByLocationUseCase;
        private readonly IGetEventByDateUseCase _getEventByDateUseCase;
        private readonly IGetEventByCategoryUseCase _getEventByCategoryUseCase;
        private readonly IGetUserEventsUseCase _getUserEventsUseCase;
        private readonly IDeleteEventUseCase _deleteEventUseCase;

        public EventController(
            AbstractValidator<CreateEventModel> eventModelValidator,
            ICreateEventUseCase createEventUseCase,
            IChangeEventInfoUseCase changeEventInfoUseCase,
            IGetAllEventsUseCase getAllEventsUseCase,
            IGetEventsByPageUseCase getEventsByPageUseCase,
            IGetEventByIdUseCase getEventByIdUseCase,
            IGetEventByTitleUseCase getEventByTitleUseCase,
            IGetEventByLocationUseCase getEventByLocationUseCase,
            IGetEventByDateUseCase getEventByDateUseCase,
            IGetEventByCategoryUseCase getEventByCategoryUseCase,
            IGetUserEventsUseCase getUserEventsUseCase,
            IDeleteEventUseCase deleteEventUseCase
            )
        {
            _eventModelValidator = eventModelValidator;
            _createEventUseCase = createEventUseCase;
            _changeEventInfoUseCase = changeEventInfoUseCase;
            _getAllEventsUseCase = getAllEventsUseCase;
            _getEventsByPageUseCase = getEventsByPageUseCase;
            _getEventByIdUseCase = getEventByIdUseCase;
            _getEventByTitleUseCase = getEventByTitleUseCase;
            _getEventByLocationUseCase = getEventByLocationUseCase;
            _getEventByDateUseCase = getEventByDateUseCase;
            _getEventByCategoryUseCase = getEventByCategoryUseCase;
            _getUserEventsUseCase = getUserEventsUseCase;
            _deleteEventUseCase = deleteEventUseCase;
        }

        [HttpPost("createEvent")]
        [Authorize(Policy = "AdminPolicy")]
        public async Task<IActionResult> CreateEvent([FromForm] CreateEventModel createEvent)
        {
            await _createEventUseCase.CreateEventAsync(createEvent);

            return Ok(new { message = "Event created successfully" });
        }

        [HttpPatch("changeEventInfo/{id}")]
        [Authorize(Policy = "AdminPolicy")]
        public async Task<IActionResult> ChangeEventInfo(int id, [FromForm] CreateEventModel modifiedEventModel)
        {
            await _changeEventInfoUseCase.ChangeEventInfoAsync(id, modifiedEventModel);

            return Ok(new { message = "ok" });
        }

        [HttpGet]
        public async Task<IActionResult> GetAllEvents()
        {
            var events = await _getAllEventsUseCase.GetAllEventsAsync();

            return Ok(events);
        }


        [HttpGet("geEventsByPage{pageNumber}/{pageSize}")]
        public async Task<IActionResult> GetEventsByPage(int pageNumber, int pageSize = 12)
        {
            if (pageNumber < 0) { return BadRequest(new { message = "Invalid page number" }); }

            if (pageSize < 0) { return BadRequest(new { message = "Invalid page size" }); }

            var result = await _getEventsByPageUseCase.GetEventsByPageAsync(pageNumber, pageSize);

            return Ok(result);
        }


        [HttpGet("findById/{id}")]
        public async Task<IActionResult> GetEventById(int id)
        {
            var @event = await _getEventByIdUseCase.GetEventByIdAsync(id);

            return Ok(@event);
        }



        [HttpGet("findByTitle/{title}")]
        public async Task<IActionResult> GetEventByTitle(string title)
        {
            var events = await _getEventByTitleUseCase.GetEventByTitleAsync(title);

            return Ok(events);

        }


        [HttpGet("findByLocation/{location}")]
        public async Task<IActionResult> GetEventByLocation(string location)
        {
            var events = await _getEventByLocationUseCase.GetEventByLocationAsync(location);

            return Ok(events);
        }



        [HttpGet("findByDate/{date}")]
        public async Task<IActionResult> GetEventsByDate(DateTime date)
        {
            var events = await _getEventByDateUseCase.GetEventsByDateAsync(date);

            return Ok(events);
        }


        [HttpGet("findByCategory/{categoryId}")]
        public async Task<IActionResult> GetEventByCategory(int categoryId)
        {
            var events = await _getEventByCategoryUseCase.GetEventsByCategoryAsync(categoryId);

            return Ok(events);
        }


        [HttpGet("getUserEvents")]
        [Authorize]
        public async Task<IActionResult> GetUserEvents()
        {
            int userId = int.Parse(User.Identity.Name);
            var events = await _getUserEventsUseCase.GetUserEventsAsync(userId);

            return Ok(events);
        }


        [HttpDelete("deleteEvent/{id}")]
        //[Authorize(Policy = "AdminPolicy")]
        public async Task<IActionResult> DeleteEventById(int id)
        {
            await _deleteEventUseCase.DeleteEventAsync(id);

            return Ok(new { message = "Delted successfully" });
        }
    }
}
