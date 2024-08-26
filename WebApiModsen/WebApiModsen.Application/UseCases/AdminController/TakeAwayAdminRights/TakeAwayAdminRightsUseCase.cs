using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;

namespace WebApiModsen.WebApiModsen.Application.UseCases.AdminController.TakeAwayAdminRights
{
    public class TakeAwayAdminRightsUseCase : ITakeAwayAdminRightsUseCase
    {
        private readonly IUnitOfWork _unitOfWork;

        public TakeAwayAdminRightsUseCase(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        public async Task TakeAwayAdminRightsAsync(int userId)
        {
            if (userId < 0) throw new InvalidIdException("Invalid user id");

            var user = await _unitOfWork.UserRepository.GetByIdAsync(userId);

            if (user.Role.Equals("Admin"))
            {
                user.Role = "User";

                await _unitOfWork.UserRepository.Update(user);
                await _unitOfWork.SaveAsync();
            }
            else
            {
                throw new AlreadyNonAdminException($"{user.Name} is not admin");
            }
            
        }
    }
}
