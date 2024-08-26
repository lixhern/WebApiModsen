namespace WebApiModsen.WebApiModsen.Application.UseCases.AdminController.GiveAdminRigths
{
    public interface IGiveAdminRightsUseCase
    {
        Task GiveAdminRightsAsync(int userId);
    }
}
