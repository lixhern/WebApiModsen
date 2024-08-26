using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;

namespace WebApiModsen.WebApiModsen.Application.UseCases.UserController.CancellationOfParticipation
{
    public class CancelOfParticipationUseCase : ICancelOfParticipationUseCase
    {
        private readonly IUnitOfWork _unitOfWork;

        public CancelOfParticipationUseCase(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        public async Task CancelOfParticipationAsync(int eventId, int userId)
        {
            if (eventId < 0)
            {
                throw new InvalidIdException("Invalid event id");
            }

            var user = await _unitOfWork.UserRepository.GetByIdAsync(userId);
            var @event = await _unitOfWork.EventRepository.GetByIdAsync(eventId);

            if (@event == null)
            {
                throw new ItemNotFoundException("Event not found");
            }

            @event.CurrentNumberOfMember--;

            await _unitOfWork.EventRepository.Update(@event);

            var userEvent = await _unitOfWork.UserEventRepository.GetByUserIdAndEventIdAsync(userId, eventId);

            await _unitOfWork.UserEventRepository.Delete(userEvent);

            await _unitOfWork.SaveAsync();
        }
    }
}
