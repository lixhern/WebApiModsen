using System;
using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Core.Service;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.ChangeEventInfo
{
    public class ChangeEventInfoUseCase : IChangeEventInfoUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;
        private readonly IImageService _imageService;

        public ChangeEventInfoUseCase(IUnitOfWork unitOfWork, IMapper mapper, IImageService imageService)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
            _imageService = imageService;
        }

        public async Task ChangeEventInfoAsync(int id, CreateEventModel modifiedEventModel)
        {

            if (id < 0)
            {
                throw new InvalidIdException("Invalid event id");
            }

            var @event = await _unitOfWork.EventRepository.GetByIdAsync(id);

            if (@event == null)
            {
                throw new ItemNotFoundException("Event not found");
            }

            var existentPath = @event.ImageUrl;

            @event = _mapper.Map(modifiedEventModel, @event);

            await _imageService.DeleteImageAsync(@event.ImagePath);

            if (modifiedEventModel.Image != null && modifiedEventModel.Image.Length > 0)
            {

                string[] paths = await _imageService.SaveImageAsync(modifiedEventModel.Image);

                if (File.Exists(existentPath))
                {
                    File.Delete(existentPath);
                }

                @event.ImageUrl = paths[1];
                @event.ImagePath = paths[0];
            }

            await _unitOfWork.EventRepository.Update(@event);
            await _unitOfWork.EventRepository.SaveAsync();
        }
    }
}
