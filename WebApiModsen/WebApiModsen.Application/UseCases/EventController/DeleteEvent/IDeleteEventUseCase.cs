namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.DeleteEvent
{
    public interface IDeleteEventUseCase
    {
        Task DeleteEventAsync(int eventId);
    }
}
