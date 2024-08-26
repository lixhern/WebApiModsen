using AutoMapper;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Web.Profiles
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<RegisterUserModel, User>();
            CreateMap<CreateEventModel, Event>();
            CreateMap<EventModel, Event>();
            CreateMap<User, ShowUserInfoModel>();
            CreateMap<Event, CreateEventModel>();
            CreateMap<Event, EventModel>();
        }
    }
}
