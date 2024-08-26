namespace WebApiModsen.WebApiModsen.Application.Exceptions
{
    public class RefreshTokenExpiredException : Exception
    {
        public RefreshTokenExpiredException()
            : base("Refresh token has expired or is invalid.")
        {
        }
    }
}
