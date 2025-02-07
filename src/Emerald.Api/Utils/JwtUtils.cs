using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Emerald.Api.Extensions;
using Emerald.Api.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace Emerald.Api.Utils;

public static class JwtUtils
{
    public static async Task<LoginResponseViewModel> GenerateJwtToken(
        string email,
        UserManager<IdentityUser> userManager,
        AppSettings appSettings)
    {
        var user = await userManager.FindByEmailAsync(email)
            ?? throw new ArgumentException("Invalid user email");

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var roles = await userManager.GetRolesAsync(user);
        claims.AddRange(roles.Select(role => new Claim("role", role)));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(appSettings.Secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: appSettings.Issuer,
            audience: appSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddHours(appSettings.ExpirationInMinutes),
            signingCredentials: creds);

        return new LoginResponseViewModel
        {
            AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
            ExpiresIn = TimeSpan.FromHours(appSettings.ExpirationInMinutes).TotalMinutes,
            User = user
        };
    }
}
