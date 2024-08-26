using AutoMapper;

using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.AdminController.GetAllAdmins
{
    public class GetAllAdminsUseCase : IGetAllAdminsUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetAllAdminsUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<IEnumerable<ShowUserInfoModel>> GetAllAdminsAsync()
        {
            var users = await _unitOfWork.UserRepository.GetAllAdminsAsync();
            var usersModel = _mapper.Map<List<ShowUserInfoModel>>(users);

            return usersModel;
        }
    }
}
