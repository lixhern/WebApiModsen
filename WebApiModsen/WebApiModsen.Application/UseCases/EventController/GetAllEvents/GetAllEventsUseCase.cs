using AutoMapper;

using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetAllEvents
{
    public class GetAllEventsUseCase : IGetAllEventsUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetAllEventsUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<IEnumerable<EventModel>> GetAllEventsAsync()
        {

            var events = await _unitOfWork.EventRepository.GetAllAsync();

            return _mapper.Map<List<EventModel>>(events);
        }
    }
}
