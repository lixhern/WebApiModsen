using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;

namespace WebApiModsen.WebApiModsen.Application.UseCases.AdminController.GiveAdminRigths
{
    public class GiveAdminRightsUseCase : IGiveAdminRightsUseCase
    {
        private readonly IUnitOfWork _unitOfWork;

        public GiveAdminRightsUseCase(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        public async Task GiveAdminRightsAsync(int userId)
        {
            if (userId < 0) throw new InvalidIdException("Invalid user id");

            var user = await _unitOfWork.UserRepository.GetByIdAsync(userId);

            if (!user.Role.Equals("Admin"))
            {
                user.Role = "Admin";

                await _unitOfWork.UserRepository.Update(user);
                await _unitOfWork.SaveAsync();
            }
            else
            {
                throw new AlreadyAdminException($"{user.Name} is already admin");
            }
            
        }
    }
}
