using Emerald.Api.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Emerald.Api.Endpoints;

public static class EmailEndpoints
{
    public static RouteGroupBuilder MapEmailEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/auth").WithTags("Email services");

        group.MapGet("/confirm-email", async (
            [FromQuery] string userId,
            [FromQuery] string code,
            [FromServices] UserManager<IdentityUser> userManager) =>
        {
            return await ConfirmEmail(userId, code, userManager);
        });

        group.MapGet("/send-email", async (
            [FromQuery] string email,
            [FromServices] UserManager<IdentityUser> userManager,
            [FromServices] IEmailSender emailSender) =>
        {
            return await SendEmail(email, userManager, emailSender);
        });

        return group;
    }

    private static async Task<IResult> ConfirmEmail(
        string userId,
        string code,
        UserManager<IdentityUser> userManager)
    {
        var user = await userManager.FindByIdAsync(userId);
        if (user == null)
            return Results.BadRequest(new { Success = false, Errors = new[] { "Invalid verification" } });

        var result = await userManager.ConfirmEmailAsync(user, code);
        return result.Succeeded
            ? Results.Ok(new { Success = true, Message = "Email confirmed" })
            : Results.BadRequest(new { Success = false, Errors = result.Errors.Select(e => e.Description) });
    }

    private static async Task<IResult> SendEmail(
        string email,
        UserManager<IdentityUser> userManager,
        IEmailSender emailSender)
    {
        var user = await userManager.FindByEmailAsync(email);
        if (user == null)
            return Results.BadRequest(new { Success = false, Errors = new[] { "User not found" } });

        var code = await userManager.GenerateEmailConfirmationTokenAsync(user);
        var callbackUrl = $"auth/confirm-email?userId={user.Id}&code={Uri.EscapeDataString(code)}";
        var result = await emailSender.SendEmailAsync(email, "Confirm your email", callbackUrl);

        return result
            ? Results.Ok(new { Success = true, Message = "Email sent" })
            : Results.BadRequest(new { Success = false, Errors = new[] { "Email send failed" } });
    }
}

