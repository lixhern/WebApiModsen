using AutoMapper;

using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.AuthController.GetCurrentUser
{
    public class GetCurrentUserUseCase : IGetCurrentUserUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetCurrentUserUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<ShowUserInfoModel> GetCurrentUserAsync(int userId)
        {
            var user = await _unitOfWork.UserRepository.GetByIdAsync(userId);

            if (user == null) throw new ItemNotFoundException("This user doesnt exist");

            return _mapper.Map<ShowUserInfoModel>(user);
        }
    }
}
