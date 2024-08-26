using FluentValidation;
using WebApiModsen.WebApiModsen.Core.Enum;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Core.Validators
{
    public class EventValidator : AbstractValidator<CreateEventModel>
    {
        public EventValidator()
        {
            RuleFor(e => e.Title).NotEmpty().MinimumLength(3).MaximumLength(30);
            RuleFor(e => e.Description).NotEmpty().MinimumLength(10).MaximumLength(125);
            RuleFor(e => e.DateOfEvent).NotEmpty();
            RuleFor(e => e.Location).NotEmpty();
            RuleFor(e => e.CategoryOfEvent)
                .Must(IsValidCategory)
                .WithMessage("Invalid category of event");
            RuleFor(e => e.MaximumOfMember).InclusiveBetween(1, 25);
        }

        private bool IsValidCategory(EventCategory category)
        {
            if ((int)category < 0 || (int)category > 16) { return false; }
            return true;
        }
    }
}
