using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;

namespace WebApiModsen.WebApiModsen.Application.UseCases.UserController.IsUserParticipation
{
    public class IsUserParticipationUseCase : IIsUserParticipationsUseCase
    {
        private readonly IUnitOfWork _unitOfWork;

        public IsUserParticipationUseCase(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        public async Task<bool> IsUserParticipationAsync(int userId, int eventId)
        {
            if (eventId < 0)
            {
                throw new InvalidIdException("Invalid event id");
            }

            return await _unitOfWork.UserEventRepository.AlreadyRegistredAsync(userId, eventId);
        }
    }
}

