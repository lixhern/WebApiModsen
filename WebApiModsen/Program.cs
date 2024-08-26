using AutoMapper;
using FluentValidation;
using FluentValidation.AspNetCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using WebApiModsen.WebApiModsen.Application.UseCases.AdminController.GetAllAdmins;
using WebApiModsen.WebApiModsen.Application.UseCases.AdminController.GiveAdminRigths;
using WebApiModsen.WebApiModsen.Application.UseCases.AdminController.TakeAwayAdminRights;
using WebApiModsen.WebApiModsen.Application.UseCases.AuthController.GetCurrentUser;
using WebApiModsen.WebApiModsen.Application.UseCases.AuthController.Login;
using WebApiModsen.WebApiModsen.Application.UseCases.AuthController.Refresh;
using WebApiModsen.WebApiModsen.Application.UseCases.AuthController.Register;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.ChangeEventInfo;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.CreateEvent;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.DeleteEvent;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetAllEvents;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByCategory;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByDate;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventById;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByLocation;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventByTitle;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetEventsByPage;
using WebApiModsen.WebApiModsen.Application.UseCases.EventController.GetUserEvents;
using WebApiModsen.WebApiModsen.Application.UseCases.UserController.CancellationOfParticipation;
using WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetAllUsers;
using WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetMembersOfEvent;
using WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetUserById;
using WebApiModsen.WebApiModsen.Application.UseCases.UserController.GetUsersByPage;
using WebApiModsen.WebApiModsen.Application.UseCases.UserController.IsUserParticipation;
using WebApiModsen.WebApiModsen.Application.UseCases.UserController.RegistrationToEvent;
using WebApiModsen.WebApiModsen.Core.Interfaces;
using WebApiModsen.WebApiModsen.Core.Models;
using WebApiModsen.WebApiModsen.Core.Service;
using WebApiModsen.WebApiModsen.Core.Validators;
using WebApiModsen.WebApiModsen.Infrastructure.Data;
using WebApiModsen.WebApiModsen.Infrastructure.Midleware;
using WebApiModsen.WebApiModsen.Web.Profiles;

namespace WebApiModsen
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            builder.Services.AddControllers();

            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "WebApiModsen", Version = "v1" });

                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "Input: Bearer token",
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
        {
            {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                },
                Array.Empty<string>()
            }
        });
            });

            builder.Services.AddAutoMapper(typeof(MappingProfile));
            builder.Services.AddScoped<UnitOfWork>();

            builder.Services.AddControllers()
            .AddFluentValidation(fv => fv.RegisterValidatorsFromAssemblyContaining<Program>());
            builder.Services.AddScoped<AbstractValidator<RegisterUserModel>, UserValidator>();
            builder.Services.AddScoped<AbstractValidator<CreateEventModel>, EventValidator>();
            builder.Services.AddLogging();

            builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();

            //Services
            builder.Services.AddScoped<IImageService, ImageService>();
            builder.Services.AddScoped<IJwtTokenService, JwtTokenService>();

            //EventController UseCases
            builder.Services.AddScoped<ICreateEventUseCase, CreateEventUseCase>();
            builder.Services.AddScoped<IChangeEventInfoUseCase, ChangeEventInfoUseCase>();
            builder.Services.AddScoped<IGetAllEventsUseCase, GetAllEventsUseCase>();
            builder.Services.AddScoped<IGetEventsByPageUseCase, GetEventsByPageUseCase>();
            builder.Services.AddScoped<IGetEventByIdUseCase, GetEventByIdUseCase>();
            builder.Services.AddScoped<IGetEventByTitleUseCase, GetEventByTitleUseCase>();
            builder.Services.AddScoped<IGetEventByLocationUseCase, GetEventByLocationUseCase>();
            builder.Services.AddScoped<IGetEventByDateUseCase, GetEventByDateUseCase>();
            builder.Services.AddScoped<IGetEventByCategoryUseCase, GetEventByCategoryUseCase>();
            builder.Services.AddScoped<IGetUserEventsUseCase, GetUserEventsUseCase>();
            builder.Services.AddScoped<IDeleteEventUseCase, DeleteEventUseCase>();
            
            //UserController UseCases
            builder.Services.AddScoped<IIsUserParticipationsUseCase, IsUserParticipationUseCase>();
            builder.Services.AddScoped<IRegistrationToEventUseCase, RegistrationToEventUseCase>();
            builder.Services.AddScoped<IGetAllUserUseCase, GetAllUsersUseCase>();
            builder.Services.AddScoped<IGetUserByIdUseCase, GetUserByIdUseCase>();
            builder.Services.AddScoped<IGetUsersByPageUseCase, GetUserByPageUseCase>();
            builder.Services.AddScoped<IGetMembersOfEventUseCase, GetMembersOfEventUseCase>();
            builder.Services.AddScoped<ICancelOfParticipationUseCase, CancelOfParticipationUseCase>();

            //AdminController UseCases
            builder.Services.AddScoped<IGetAllAdminsUseCase, GetAllAdminsUseCase>();
            builder.Services.AddScoped<IGiveAdminRightsUseCase, GiveAdminRightsUseCase>();
            builder.Services.AddScoped<ITakeAwayAdminRightsUseCase, TakeAwayAdminRightsUseCase>();
            
            //AuthController UseCases
            builder.Services.AddScoped<IRegisterUseCase, RegisterUseCase>();
            builder.Services.AddScoped<ILoginUseCase,  LoginUseCase>();
            builder.Services.AddScoped<IRefreshUseCase, RefreshUseCase>();
            builder.Services.AddScoped<IGetCurrentUserUseCase, GetCurrentUserUseCase>();


            var key = Encoding.ASCII.GetBytes(builder.Configuration["Jwt:Key"]);
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = builder.Configuration["Jwt:Issuer"],
                    ValidAudience = builder.Configuration["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                };
            });

            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("AdminPolicy", policy => policy.RequireRole("Admin"));
                options.AddPolicy("UserPolicy", policy => policy.RequireRole("User", "Admin"));
            });

            builder.Services.AddCors(options =>
            {
                options.AddPolicy("AllowAngularApp",
                    policy =>
                    {
                        policy.WithOrigins("http://localhost:4200") 
                              .AllowAnyHeader()
                              .AllowAnyMethod()
                              .AllowCredentials();
                    });
            });

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseMiddleware<ExceptionHandlingMidleware>();

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCors("AllowAngularApp");

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }

    }
}
