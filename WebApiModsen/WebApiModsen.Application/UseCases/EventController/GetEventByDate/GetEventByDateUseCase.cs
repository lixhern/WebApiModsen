using AutoMapper;

using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByDate
{
    public class GetEventByDateUseCase : IGetEventByDateUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetEventByDateUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<IEnumerable<EventModel>> GetEventsByDateAsync(DateTime date)
        {
            var events = await _unitOfWork.EventRepository.GetEventByDateAsync(date);

            return _mapper.Map<List<EventModel>>(events);
        }
    }
}
