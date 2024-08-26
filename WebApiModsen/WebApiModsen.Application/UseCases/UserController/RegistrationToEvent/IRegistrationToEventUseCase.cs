namespace WebApiModsen.WebApiModsen.Application.UseCases.UserController.RegistrationToEvent
{
    public interface IRegistrationToEventUseCase
    {
        Task RegistrationToEventAsync(int eventId, int userId);
    }
}
