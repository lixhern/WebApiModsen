using AutoMapper;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByLocation
{
    public class GetEventByLocationUseCase : IGetEventByLocationUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetEventByLocationUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<IEnumerable<EventModel>> GetEventByLocationAsync(string location)
        {
            var events = await _unitOfWork.EventRepository.GetEventByLocationAsync(location);

            return _mapper.Map<List<EventModel>>(events);
        }
    }
}
