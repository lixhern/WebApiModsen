using Microsoft.AspNetCore.Mvc;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.AuthController.Register
{
    public interface IRegisterUseCase
    {
        Task RegisterAsync(RegisterUserModel model);
    }
}
