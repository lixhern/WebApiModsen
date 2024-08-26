using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;

namespace WebApiModsen.WebApiModsen.Application.UseCases.UserController.RegistrationToEvent
{
    public class RegistrationToEventUseCase : IRegistrationToEventUseCase
    {
        private readonly IUnitOfWork _unitOfWork;

        public RegistrationToEventUseCase(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        public async Task RegistrationToEventAsync(int eventId, int userId)
        {
            if (eventId < 0)
            {
                throw new InvalidIdException("Invalid event id");
            }

            if (await _unitOfWork.UserEventRepository.AlreadyRegistredAsync(userId, eventId))
            {
                throw new AlreadyRegiteredException("This user is already registered");
            }

            var @event = await _unitOfWork.EventRepository.GetByIdAsync(eventId);
            if (@event.CurrentNumberOfMember == @event.MaximumOfMember)
            {
                throw new NoSpotsAvaliableException("No spots available for this event");
            }

            var userEvent = new UserEvent
            {
                UserId = userId,
                EventId = eventId,
                RegistrationDate = DateTime.UtcNow.AddHours(3),
            };

            await _unitOfWork.UserEventRepository.InsertAsync(userEvent);

            @event.CurrentNumberOfMember++;
            await _unitOfWork.EventRepository.Update(@event);

            var user = await _unitOfWork.UserRepository.GetByIdAsync(userId);
            user.DateOfRegistrationOnEvent = DateTime.UtcNow.AddHours(3);
            await _unitOfWork.UserRepository.Update(user);

            await _unitOfWork.SaveAsync();
        }
    }
}
