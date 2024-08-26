using AutoMapper;

using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetAllUsers
{
    public class GetAllUsersUseCase : IGetAllUserUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetAllUsersUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<IEnumerable<ShowUserInfoModel>> GetAllUsersAsync()
        {
            var users = await _unitOfWork.UserRepository.GetAllAsync();

            var usersModel = _mapper.Map<List<ShowUserInfoModel>>(users);

            return usersModel;
        }
    }
}
