using AutoMapper;

using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.AuthController.Register
{
    public class RegisterUseCase : IRegisterUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;


        public RegisterUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task RegisterAsync(RegisterUserModel model)
        {
            if (await _unitOfWork.UserRepository.UserEcistsByEmailAsync(model.Email))
            {
                throw new InvalidEmailException("User with this email already exist");
            }

            var user = _mapper.Map<User>(model);

            await _unitOfWork.UserRepository.InsertAsync(user);
            await _unitOfWork.UserRepository.SaveAsync();
        }
    }
}
