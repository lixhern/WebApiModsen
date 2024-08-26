using WebApiModsen.WebApiModsen.Core.Enum;

namespace WebApiModsen.WebApiModsen.Core.Models
{
    public class Event : BaseUserEventModel
    {
        //public int AuthorId { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public DateTime DateOfEvent { get; set; }
        public string Location { get; set; }
        public EventCategory CategoryOfEvent { get; set; }
        public int MaximumOfMember { get; set; }
        public int CurrentNumberOfMember { get; set; }
        public string ImageUrl { get; set; }
        public string ImagePath { get; set; }

    }
}
