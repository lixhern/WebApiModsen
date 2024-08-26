using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Core.Service;

namespace WebApiModsen.WebApiModsen.Application.UseCases.AuthController.Refresh
{
    public class RefreshUseCase : IRefreshUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IJwtTokenService _jwtTokenService;

        public RefreshUseCase(IUnitOfWork unitOfWork, IJwtTokenService jwtTokenService)
        {
            _unitOfWork = unitOfWork;
            _jwtTokenService = jwtTokenService;
        }

        public async Task<LoginResponse> RefreshAsync(string refreshToken)
        {
            var storedRefreshToken = await _unitOfWork.RefreshTokenRepository.GetRefreshTokenAsync(refreshToken);

            if (storedRefreshToken == null || storedRefreshToken.ExpiryDate <= DateTime.UtcNow)
            {
                throw new RefreshTokenExpiredException();
            }

            var user = await _unitOfWork.UserRepository.GetByIdAsync(storedRefreshToken.UserId);

            var newAccessToken = _jwtTokenService.GenerateJwtToken(user);
            var newRefreshToken = _jwtTokenService.GenerateRefreshToken(user.Id);

            await _unitOfWork.RefreshTokenRepository.Delete(storedRefreshToken);
            await _unitOfWork.RefreshTokenRepository.InsertAsync(newRefreshToken);
            await _unitOfWork.RefreshTokenRepository.SaveAsync();

            return new LoginResponse { AccessToken = newAccessToken, RefreshToken = newRefreshToken.Token };
        }
    }
}
