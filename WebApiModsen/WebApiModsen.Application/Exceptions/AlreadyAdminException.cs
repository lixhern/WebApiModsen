namespace WebApiModsen.WebApiModsen.Application.Exceptions
{
    public class AlreadyAdminException : Exception
    {
        public AlreadyAdminException(string message) : base(message) { }
    }
}
