using System.Net;
using System.Text.Json;
using WebApiModsen.WebApiModsen.Application.Exceptions;

namespace WebApiModsen.WebApiModsen.Infrastructure.Midleware
{
    public class ExceptionHandlingMidleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionHandlingMidleware> _logger;

        public ExceptionHandlingMidleware(RequestDelegate next, ILogger<ExceptionHandlingMidleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (InvalidIdException ex)
            {
                _logger.LogError(ex, "invalid id");
                await HandleExceptionAsync(context, ex);
            }
            catch (ItemNotFoundException ex)
            {
                _logger.LogError(ex, "not found");
                await HandleExceptionAsync(context, ex);
            }
            catch (AlreadyAdminException ex)
            {
                _logger.LogError(ex, "not found");
                await HandleExceptionAsync(context, ex);
            }
            catch (AlreadyNonAdminException ex)
            {
                _logger.LogError(ex, "not found");
                await HandleExceptionAsync(context, ex);
            }
            catch (RefreshTokenExpiredException ex)
            {
                _logger.LogError(ex, "not found");
                await HandleExceptionAsync(context, ex);
            }
            catch (InvalidEmailException ex)
            {
                _logger.LogError(ex, "not found");
                await HandleExceptionAsync(context, ex);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled exception occurred.");
                await HandleExceptionAsync(context, ex);
            }
        }

        private Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;

            var response = new
            {
                context.Response.StatusCode,
                Message = "An unexpected error occurred.",
                Detailed = exception.Message
            };

            var jsonRespone = JsonSerializer.Serialize(response);

            return context.Response.WriteAsync(jsonRespone);
        }
    }
}
