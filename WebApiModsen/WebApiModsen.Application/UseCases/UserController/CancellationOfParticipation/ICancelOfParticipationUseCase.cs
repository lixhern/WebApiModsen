namespace WebApiModsen.WebApiModsen.Application.UseCases.UserController.CancellationOfParticipation
{
    public interface ICancelOfParticipationUseCase
    {
        Task CancelOfParticipationAsync(int eventId, int userId);
    }
}
