using System.Collections;

namespace WebApiModsen.WebApiModsen.Core.Models
{
    public class BaseUserEventModel
    {
        public int Id { get; set; }
        public ICollection<UserEvent> UserEvents { get; set; } = new List<UserEvent>();
    }
}
