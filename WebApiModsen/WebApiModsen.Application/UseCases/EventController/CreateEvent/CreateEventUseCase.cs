using AutoMapper;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Core.Service;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.CreateEvent
{
    public class CreateEventUseCase : ICreateEventUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;
        private readonly IImageService _imageService;

        public CreateEventUseCase(IUnitOfWork unitOfWork, IMapper mapper, IImageService imageService)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _imageService = imageService;
        }

        public async Task CreateEventAsync(CreateEventModel createEventModel)
        {
            var @event = _mapper.Map<Event>(createEventModel);

            if (createEventModel.Image != null && createEventModel.Image.Length > 0)
            {
                string[] paths = await _imageService.SaveImageAsync(createEventModel.Image);

                @event.ImageUrl = paths[1];
                @event.ImagePath = paths[0];
            }

            await _unitOfWork.EventRepository.InsertAsync(@event);
            await _unitOfWork.EventRepository.SaveAsync();

        }
    }
}
