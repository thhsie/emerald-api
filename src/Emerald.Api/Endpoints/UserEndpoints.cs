using Emerald.Api.ViewModels;
using Microsoft.AspNetCore.Identity;

namespace Emerald.Api.Endpoints;

public static class UserEndpoints
{
    public static RouteGroupBuilder MapUserEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/auth").WithTags("User management");

        group.MapPost("/reset-password", ResetPasswordAsync)
        .RequireAuthorization()
        .Produces(200)
        .ProducesProblem(400);

        group.MapGet("/user", GetUserAsync)
        .RequireAuthorization();

        return group;
    }

    private static async Task<IResult> ResetPasswordAsync(
        ResetPasswordViewModel resetPassword,
        UserManager<IdentityUser> userManager)
    {
        var user = await userManager.FindByEmailAsync(resetPassword.Email);
        if (user == null)
            return Results.BadRequest(new { Success = false, Errors = new[] { "User not found" } });

        if (user.PasswordHash is null)
            return Results.BadRequest(new { Success = false, Errors = new[] { "External user account" } });

        var result = await userManager.ChangePasswordAsync(
            user, resetPassword.CurrentPassword, resetPassword.NewPassword);

        return result.Succeeded
            ? Results.Ok(new { Success = true, Message = "Password reset successful" })
            : Results.BadRequest(new { Success = false, Errors = result.Errors.Select(e => e.Description) });
    }

    private static async Task<IResult> GetUserAsync(
        string email,
        UserManager<IdentityUser> userManager)
    {
        var user = await userManager.FindByEmailAsync(email);
        return user == null
            ? Results.BadRequest(new { Success = false, Errors = new[] { "User not found" } })
            : Results.Ok(new { Success = true, Data = user });
    }
}

