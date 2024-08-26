using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApiModsen.WebApiModsen.Application.UseCases.UserController.CancellationOfParticipation;
using WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetAllUsers;
using WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetMembersOfEvent;
using WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetUserById;
using WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetUsersByPage;
using WebApiModsen.WebApiModsen.Application.UseCases.UserController.IsUserParticipation;
using WebApiModsen.WebApiModsen.Application.UseCases.UserController.RegistrationToEvent;

namespace WebApiModsen.WebApiModsen.Web.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IIsUserParticipationsUseCase _isUserParticipationUseCase;
        private readonly IRegistrationToEventUseCase _registrationToEventUseCase;
        private readonly IGetAllUserUseCase _getAllUsersUseCase;
        private readonly IGetUsersByPageUseCase _getUsersByPageUseCase;
        private readonly IGetUserByIdUseCase _getUserByIdUseCase;
        private readonly IGetMembersOfEventUseCase _getMembersOfEventUseCase;
        private readonly ICancelOfParticipationUseCase _cancelOfParticipationUseCase;

        public UserController(
            IIsUserParticipationsUseCase isUserParticipationUseCase,
            IRegistrationToEventUseCase registrationToEventUseCase,
            IGetAllUserUseCase getAllUserUseCase,
            IGetUsersByPageUseCase getUsersByPageUseCase,
            IGetUserByIdUseCase getUserByIdUseCase,
            IGetMembersOfEventUseCase getMembersOfEventUseCase,
            ICancelOfParticipationUseCase cancelOfParticipationUseCase
            )
        {
            _isUserParticipationUseCase = isUserParticipationUseCase;
            _registrationToEventUseCase = registrationToEventUseCase;
            _getAllUsersUseCase = getAllUserUseCase;
            _getUsersByPageUseCase = getUsersByPageUseCase;
            _getUserByIdUseCase = getUserByIdUseCase;
            _getMembersOfEventUseCase = getMembersOfEventUseCase;
            _cancelOfParticipationUseCase = cancelOfParticipationUseCase;
        }


        [HttpGet("isUserParticipation/{eventId}")]
        public async Task<IActionResult> IsUserParticipation(int eventId)
        {
            int userId = int.Parse(User.Identity.Name);

            return Ok(await _isUserParticipationUseCase.IsUserParticipationAsync(userId, eventId));
        }

        [HttpPost("registerToEvent/{eventId}")]
        [Authorize]
        public async Task<IActionResult> RegistrationToEvent(int eventId)
        {
            var userId = int.Parse(User.Identity.Name);

            await _registrationToEventUseCase.RegistrationToEventAsync(eventId, userId);

            return Ok(new { message = "success" });
        }

        [HttpGet("getAllUsers")]
        public async Task<IActionResult> GetAllUsers()
        {
            var usersModel = await _getAllUsersUseCase.GetAllUsersAsync();

            return Ok(usersModel);
        }


        [HttpGet("getUsersByPage{pageNumber}/{pageSize}")]
        public async Task<IActionResult> GetUsersByPage(int pageNumber, int pageSize = 10)
        {
            var result = await _getUsersByPageUseCase.GetUsersByPageAsync(pageNumber, pageSize);

            return Ok(result);
        }


        [HttpGet("getUserById{id}")]
        public async Task<IActionResult> GetUserById(int id)
        {
            var user = await _getUserByIdUseCase.GetUserByIdAsync(id);

            return Ok(user);
        }


        [HttpGet("getMembersOfEvent/{eventId}")]
        public async Task<IActionResult> GetMembersOfEvent(int eventId)
        {
            var users = await _getMembersOfEventUseCase.GetMembersOfEventAsync(eventId);

            return Ok(users);
        }


        [HttpDelete("removeFromParticipation/{eventId}")]
        [Authorize]
        public async Task<IActionResult> CancellationOfParticipation(int eventId)
        {
            int userId = int.Parse(User.Identity.Name);

            await _cancelOfParticipationUseCase.CancelOfParticipationAsync(eventId, userId);

            return Ok(new { message = "Ok" });
        }

    }
}
