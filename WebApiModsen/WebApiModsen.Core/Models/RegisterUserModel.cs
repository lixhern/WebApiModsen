using System.Text.Json.Serialization;

namespace WebApiModsen.WebApiModsen.Core.Models
{
    public class RegisterUserModel
    {
        public string Name { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public DateTime DateOfBirth { get; set; }
    }
}
