using AutoMapper;

using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetMembersOfEvent
{
    public class GetMembersOfEventUseCase : IGetMembersOfEventUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetMembersOfEventUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<IEnumerable<ShowUserInfoModel>> GetMembersOfEventAsync(int eventId)
        {
            if (eventId < 0)
            {
                throw new InvalidIdException("Invalid event id");
            }

            var @event = await _unitOfWork.EventRepository.GetByIdAsync(eventId);

            if (@event == null)
            {
                throw new ItemNotFoundException("Event doesn't exist");
            }

            var users = await _unitOfWork.UserRepository.GetParticipantsOfEventAsync(eventId);

            var usersModel = _mapper.Map<List<ShowUserInfoModel>>(users);

            return usersModel;
        }
    }
}
