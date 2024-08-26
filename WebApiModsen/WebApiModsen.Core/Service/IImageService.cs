namespace WebApiModsen.WebApiModsen.Core.Service
{
    public interface IImageService
    {
        Task<string[]> SaveImageAsync(IFormFile file);
        Task DeleteImageAsync(string path);
    }
}
