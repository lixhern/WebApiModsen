namespace WebApiModsen.WebApiModsen.Application.Exceptions
{
    public class AlreadyNonAdminException : Exception
    {
        public AlreadyNonAdminException(string message) : base(message) { }
    }
}
