using Emerald.Api.Extensions;
using Emerald.Api.Interfaces;
using Emerald.Api.Utils;
using Emerald.Api.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Emerald.Api.Endpoints;

public static class AuthEndpoints
{
    public static RouteGroupBuilder MapAuthEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/auth").WithTags("Authentication");

        group.MapPost("/register", async (
            [FromBody] RegisterUserViewModel registerUser,
            [FromServices] UserManager<IdentityUser> userManager,
            [FromServices] SignInManager<IdentityUser> signInManager,
            [FromServices] IEmailSender emailSender,
            [FromServices] IOptions<AppSettings> appSettings) =>
        {
            return await RegisterUser(registerUser, userManager, signInManager, emailSender, appSettings);
        }).Produces(200).ProducesProblem(400);

        group.MapPost("/login", async (
            [FromBody] LoginUserViewModel loginUser,
            [FromServices] UserManager<IdentityUser> userManager,
            [FromServices] SignInManager<IdentityUser> signInManager,
            [FromServices] IOptions<AppSettings> appSettings) =>
        {
            return await LoginUser(loginUser, userManager, signInManager, appSettings);
        }).Produces(200).ProducesProblem(400);

        return group;
    }

    private static async Task<IResult> RegisterUser(
        RegisterUserViewModel registerUser,
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IEmailSender emailSender,
        IOptions<AppSettings> appSettings)
    {
        var user = new IdentityUser
        {
            UserName = registerUser.Email,
            Email = registerUser.Email,
            EmailConfirmed = !registerUser.SendEmailConfirmation
        };

        var createResult = await userManager.CreateAsync(user, registerUser.Password);
        if (!createResult.Succeeded)
            return Results.BadRequest(new { Success = false, Errors = createResult.Errors.Select(e => e.Description) });

        if (registerUser.SendEmailConfirmation)
        {
            var code = await userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = $"auth/confirm-email?userId={user.Id}&code={Uri.EscapeDataString(code)}";
            await emailSender.SendEmailAsync(user.Email!, "Confirm your email", callbackUrl);
        }

        await signInManager.SignInAsync(user, false);
        var token = await JwtUtils.GenerateJwtToken(user.Email!, userManager, appSettings.Value);

        return Results.Ok(new { Success = true, Data = token });
    }

    private static async Task<IResult> LoginUser(
        LoginUserViewModel loginUser,
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IOptions<AppSettings> appSettings)
    {
        var result = await signInManager.PasswordSignInAsync(
            loginUser.Email, loginUser.Password, false, true);

        if (!result.Succeeded)
            return Results.BadRequest(new { Success = false, Errors = new[] { "Invalid credentials" } });

        var token = await JwtUtils.GenerateJwtToken(loginUser.Email, userManager, appSettings.Value);
        return Results.Ok(new { Success = true, Data = token });
    }
}
