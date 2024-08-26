using FluentValidation;
using WebApiModsen.WebApiModsen.Core.Models;

namespace WebApiModsen.WebApiModsen.Core.Validators
{
    public class UserValidator : AbstractValidator<RegisterUserModel>
    {
        public UserValidator()
        {
            RuleFor(u => u.Name)
                .NotEmpty()
                .MaximumLength(20)
                .Matches(@"^[a-zA-Zа-яА-Я]+$")
                .WithMessage("The name cannot contain numbers or specials caracters");
            RuleFor(u => u.LastName)
                .NotEmpty()
                .MaximumLength(20)
                .Matches(@"^[a-zA-Zа-яА-Я]+$")
                .WithMessage("The last name cannot contain numbers or specials caracters");
            RuleFor(u => u.Email)
                .NotEmpty()
                .Matches(@"^[^@\s]+@[^@\s]+\.[^@\s]+$")
                .WithMessage("Invalid email format");
            RuleFor(u => u.Password).NotEmpty();
            RuleFor(u => u.DateOfBirth)
                .NotEmpty();

        }
    }
}
