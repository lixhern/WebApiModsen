using AutoMapper;

using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByTitle
{
    public class GetEventByTitleUseCase : IGetEventByTitleUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetEventByTitleUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<IEnumerable<EventModel>> GetEventByTitleAsync(string title)
        {
            var events = await _unitOfWork.EventRepository.GetEventByTitleAsync(title);

            return _mapper.Map<List<EventModel>>(events);
        }
    }
}
