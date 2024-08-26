using AutoMapper;

using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Application.Exceptions;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventById
{
    public class GetEventByIdUseCase : IGetEventByIdUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetEventByIdUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<EventModel> GetEventByIdAsync(int id)
        {
            if (id < 0) throw new InvalidIdException("Invalid event id");

            var @event = await _unitOfWork.EventRepository.GetByIdAsync(id);

            if (@event == null) throw new ItemNotFoundException("The event does not exist");

            return _mapper.Map<EventModel>(@event);
        }
    }
}
