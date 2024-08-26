using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Application.UseCases.AuthController.GetCurrentUser;
using WebApiModsen.WebApiModsen.Application.UseCases.AuthController.Login;
using WebApiModsen.WebApiModsen.Application.UseCases.AuthController.Refresh;
using WebApiModsen.WebApiModsen.Application.UseCases.AuthController.Register;


namespace WebApiModsen.WebApiModsen.Web.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IRegisterUseCase _registerUseCase;
        private readonly ILoginUseCase _loginUseCase;
        private readonly IRefreshUseCase _refreshUseCase;
        private readonly IGetCurrentUserUseCase _getCurrentUserUseCase;

        public AuthController(
            IRegisterUseCase registerUseCase,
            ILoginUseCase loginUseCase,
            IRefreshUseCase refreshUseCase,
            IGetCurrentUserUseCase getCurrentUserUseCase
            )
        {
            _registerUseCase = registerUseCase;
            _loginUseCase = loginUseCase;
            _refreshUseCase = refreshUseCase;
            _getCurrentUserUseCase = getCurrentUserUseCase;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserModel model)
        {
            await _registerUseCase.RegisterAsync(model);

            return Ok(new {message = "Ok"});
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginUserModel model)
        {
            var result = await _loginUseCase.LoginAsync(model);

            return Ok(result);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] string refreshToken)
        {
            var result = await _refreshUseCase.RefreshAsync(refreshToken);

            return Ok(result);
        }

        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUser()
        {
            var userId = int.Parse(User.Identity.Name);
            var user = await _getCurrentUserUseCase.GetCurrentUserAsync(userId);

            return Ok(user);
        }


    }
}
