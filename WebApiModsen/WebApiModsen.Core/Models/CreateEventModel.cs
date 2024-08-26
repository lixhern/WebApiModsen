using WebApiModsen.WebApiModsen.Core.Enum;

namespace WebApiModsen.WebApiModsen.Core.Models
{
    public class CreateEventModel
    {
        public string? Title { get; set; }
        public string? Description { get; set; }
        public DateTime? DateOfEvent { get; set; }
        public string? Location { get; set; }
        public EventCategory CategoryOfEvent { get; set; }
        public int? MaximumOfMember { get; set; }
        public IFormFile? Image { get; set; }
    }
}
