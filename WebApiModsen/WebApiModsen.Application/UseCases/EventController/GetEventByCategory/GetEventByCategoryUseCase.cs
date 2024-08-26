using AutoMapper;

using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Enum;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByCategory
{
    public class GetEventByCategoryUseCase : IGetEventByCategoryUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetEventByCategoryUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<IEnumerable<EventModel>> GetEventsByCategoryAsync(int categoryId)
        {
            if (categoryId > 16 || categoryId < 0) throw new InvalidIdException("Invalid category Id");

            EventCategory category = (EventCategory)categoryId;

            var events = await _unitOfWork.EventRepository.GetEventByCategoryAsync(category);

            return _mapper.Map<List<EventModel>>(events);
        }
    }
}
