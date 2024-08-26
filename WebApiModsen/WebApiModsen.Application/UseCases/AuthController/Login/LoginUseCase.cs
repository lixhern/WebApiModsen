using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Core.Service;

namespace WebApiModsen.WebApiModsen.Application.UseCases.AuthController.Login
{
    public class LoginUseCase : ILoginUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IJwtTokenService _jwtTokenService;

        public LoginUseCase(IUnitOfWork unitOfWork, IJwtTokenService jwtTokenService)
        {
            _unitOfWork = unitOfWork;
            _jwtTokenService = jwtTokenService;
        }

        public async Task<LoginResponse> LoginAsync(LoginUserModel model)
        {
            var existingUser = await _unitOfWork.UserRepository.GetUserForLoginAsync(model.Email, model.Password);

            if (existingUser == null) throw new ItemNotFoundException("This user doesnt exist");
            
            var token = _jwtTokenService.GenerateJwtToken(existingUser);
            var refreshToken = _jwtTokenService.GenerateRefreshToken(existingUser.Id);
            
            await _unitOfWork.RefreshTokenRepository.InsertAsync(refreshToken);
            await _unitOfWork.RefreshTokenRepository.SaveAsync();

            return new LoginResponse { AccessToken = token, RefreshToken = refreshToken.Token, UserName = existingUser.Name };
        }
    }
}
