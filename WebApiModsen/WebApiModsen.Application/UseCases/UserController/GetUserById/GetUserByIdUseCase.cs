using AutoMapper;

using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetUserById
{
    public class GetUserByIdUseCase : IGetUserByIdUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetUserByIdUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<ShowUserInfoModel> GetUserByIdAsync(int userId)
        {
            if (userId < 0)
            {
                throw new InvalidIdException("Invalid user id");
            }

            var user = await _unitOfWork.UserRepository.GetByIdAsync(userId);

            ShowUserInfoModel userModel = _mapper.Map<ShowUserInfoModel>(user);

            return userModel;
        }
    }
}
