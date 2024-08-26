
namespace WebApiModsen.WebApiModsen.Core.Service
{
    public class ImageService : IImageService
    {
        private readonly IWebHostEnvironment _environment;

        public ImageService(IWebHostEnvironment environment)
        {
            _environment = environment;
        }

        public async Task<string[]> SaveImageAsync(IFormFile image)
        {
            if (image == null || image.Length == 0)
            {
                return null;
            }

            var fileName = $"{Guid.NewGuid()}{Path.GetExtension(image.FileName)}";
            var uploadsFolder = Path.Combine(_environment.WebRootPath, "images");
            var filePath = Path.Combine(uploadsFolder, fileName);

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await image.CopyToAsync(stream);
            }

            string[] result = new string[2];

            result[0] = filePath;
            result[1] = $"https://localhost:7029/images/{fileName}";

            return result;
        }

        public async Task DeleteImageAsync(string path)
        {
            await Task.Run(() =>
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            });
        }
    }
}
