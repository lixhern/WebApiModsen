using Microsoft.AspNetCore.Mvc;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Application.UseCases.EventController.ChangeEventInfo
{
    public interface IChangeEventInfoUseCase
    {
        Task ChangeEventInfoAsync(int id, [FromForm] CreateEventModel modifiedEventModel);
    }
}
