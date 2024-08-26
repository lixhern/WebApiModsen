namespace WebApiModsen.WebApiModsen.Application.UseCases.AdminController.TakeAwayAdminRights
{
    public interface ITakeAwayAdminRightsUseCase
    {
        Task TakeAwayAdminRightsAsync(int userId);
    }
}
