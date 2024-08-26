using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Service;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.DeleteEvent
{
    public class DeleteEventUseCase : IDeleteEventUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IImageService _imageService;

        public DeleteEventUseCase(IUnitOfWork unitOfWork, IImageService imageService)
        {
            _unitOfWork = unitOfWork;
            _imageService = imageService;
        }

        public async Task DeleteEventAsync(int eventId)
        {
            if (eventId < 0) throw new InvalidIdException("Invalid event id");

            var @event = await _unitOfWork.EventRepository.GetByIdAsync(eventId);

            await _imageService.DeleteImageAsync(@event.ImagePath);
            await _unitOfWork.EventRepository.DeleteByIdAsync(eventId);
            await _unitOfWork.SaveAsync();
        }
    }
}
