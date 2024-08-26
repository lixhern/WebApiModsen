using AutoMapper;

using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetUserEvents
{
    public class GetUserEventsUseCase : IGetUserEventsUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetUserEventsUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<IEnumerable<EventModel>> GetUserEventsAsync(int userId)
        {
            if (userId < 0) throw new InvalidIdException("Invalid user id");

            var events = await _unitOfWork.EventRepository.GetUserEventsAsync(userId);

            return _mapper.Map<List<EventModel>>(events);
        }
    }
}
