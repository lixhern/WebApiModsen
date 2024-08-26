namespace WebApiModsen.WebApiModsen.Core.Models
{
    public class User : BaseUserEventModel
    {
        public string Name { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public DateTime DateOfBirth { get; set; }
        public DateTime? DateOfRegistrationOnEvent { get; set; }
        public string Role { get; set; }
        public User()
        {
            Role = "User";
        }

    }
}
