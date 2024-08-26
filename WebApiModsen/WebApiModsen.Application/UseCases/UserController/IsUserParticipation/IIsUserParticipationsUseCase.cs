namespace WebApiModsen.WebApiModsen.Application.UseCases.UserController.IsUserParticipation
{
    public interface IIsUserParticipationsUseCase
    {
        Task<bool> IsUserParticipationAsync(int userId, int eventId);
    }
}
