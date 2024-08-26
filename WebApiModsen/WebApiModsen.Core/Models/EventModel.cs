using WebApiModsen.WebApiModsen.Core.Enum;

namespace WebApiModsen.WebApiModsen.Core.Models
{
    public class EventModel
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public DateTime DateOfEvent { get; set; }
        public string Location { get; set; }
        public EventCategory CategoryOfEvent { get; set; }
        public int MaximumOfMember { get; set; }
        public int CurrentNumberOfMember { get; set; }
        public string ImageUrl { get; set; }
    }
}
