using AutoMapper;

using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventsByPage
{
    public class GetEventsByPageUseCase : IGetEventsByPageUseCase
    {
        public IUnitOfWork _unitOfWork;
        public IMapper _mapper;

        public GetEventsByPageUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<ItemPageResult<EventModel>> GetEventsByPageAsync(int pageNumber, int pageSize)
        {
            if (pageNumber <= 0) throw new InvalidIdException("Invalid page number");

            if (pageSize <= 0) throw new InvalidIdException("Invalid page size");

            var events = await _unitOfWork.EventRepository.GetByPageAsync(pageNumber, pageSize);

            var result = new ItemPageResult<EventModel>
            {
                TotalItems = await _unitOfWork.EventRepository.GetTotalCountAsync(),
                PageNumber = pageNumber,
                PageSize = pageSize,
                Items = _mapper.Map<List<EventModel>>(events)
            };

            return result;
        }
    }
}
