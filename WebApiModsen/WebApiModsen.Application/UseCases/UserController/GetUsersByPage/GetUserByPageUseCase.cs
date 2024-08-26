using AutoMapper;

using WebApiModsen.WebApiModsen.Application.Exceptions;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetUsersByPage
{
    public class GetUserByPageUseCase : IGetUsersByPageUseCase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetUserByPageUseCase(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<ItemPageResult<ShowUserInfoModel>> GetUsersByPageAsync(int pageNumber, int pageSize)
        {
            if (pageNumber <= 0)
            {
                throw new InvalidIdException("Invalid page number");
            }

            if (pageSize <= 0)
            {
                throw new InvalidIdException("Invalid page size");
            }

            var users = await _unitOfWork.UserRepository.GetByPageAsync(pageNumber, pageSize);

            var result = new ItemPageResult<ShowUserInfoModel>
            {
                TotalItems = users.Count(),
                PageNumber = pageNumber,
                PageSize = pageSize,
                Items = _mapper.Map<List<ShowUserInfoModel>>(users)
            };

            return result;
        }
    }
}
