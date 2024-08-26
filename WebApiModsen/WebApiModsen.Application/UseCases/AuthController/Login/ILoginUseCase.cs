using Microsoft.AspNetCore.Mvc;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.AuthController.Login
{
    public interface ILoginUseCase
    {
        Task<LoginResponse> LoginAsync(LoginUserModel model);
    }
}
