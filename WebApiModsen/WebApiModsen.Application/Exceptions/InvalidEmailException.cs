namespace WebApiModsen.WebApiModsen.Application.Exceptions
{
    public class InvalidEmailException : Exception
    {
        public InvalidEmailException(string message) : base(message) { }
    }
}
