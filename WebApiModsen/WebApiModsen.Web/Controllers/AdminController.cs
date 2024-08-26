using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using WebApiModsen.WebApiModsen.Application.UseCases.AdminController.GetAllAdmins;
using WebApiModsen.WebApiModsen.Application.UseCases.AdminController.GiveAdminRigths;
using WebApiModsen.WebApiModsen.Application.UseCases.AdminController.TakeAwayAdminRights;

namespace WebApiModsen.WebApiModsen.Web.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Policy = "AdminPolicy")]
    public class AdminController : ControllerBase
    {
        private readonly IGetAllAdminsUseCase _getAllAdminsUseCase;
        private readonly IGiveAdminRightsUseCase _giveAdminRightsUseCase;
        private readonly ITakeAwayAdminRightsUseCase _takeAwayAdminRightsUseCase;

        public AdminController(
            IGetAllAdminsUseCase getAllAdminsUseCase,
            IGiveAdminRightsUseCase giveAdminRightsUseCase,
            ITakeAwayAdminRightsUseCase takeAwayAdminRightsUseCase
            )
        {
            _getAllAdminsUseCase = getAllAdminsUseCase;
            _giveAdminRightsUseCase = giveAdminRightsUseCase;
            _takeAwayAdminRightsUseCase = takeAwayAdminRightsUseCase;
        }

        [HttpGet("getAllAdmins")]
        public async Task<IActionResult> GetAllAdmins()
        {
            var admins = await _getAllAdminsUseCase.GetAllAdminsAsync();

            return Ok(admins);
        }

        [HttpGet("giveAdminRights{id}")]
        [Authorize(Policy = "AdminPolicy")]
        public async Task<IActionResult> GiveADminRigths(int id)
        {
            await _giveAdminRightsUseCase.GiveAdminRightsAsync(id);

            return Ok();
        }

        [HttpGet("takeAwayAdminRights{id}")]
        [Authorize(Policy = "AdminPolicy")]
        public async Task<IActionResult> TakeAwayAdminRights(int id)
        {
            await _takeAwayAdminRightsUseCase.TakeAwayAdminRightsAsync(id);

            return Ok();
        }

    }
}
