using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Emerald.Api.Extensions;
using Emerald.Api.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Emerald.Api.Controllers;

[Route("auth")]
public class AuthController : MainController
{
    public readonly SignInManager<IdentityUser> _signInManager;
    public readonly UserManager<IdentityUser> _userManager;
    public readonly AppSettings _appSettings;

    public AuthController(SignInManager<IdentityUser> signInManager,
                          UserManager<IdentityUser> userManager,
                          IOptions<AppSettings> appSettings)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _appSettings = appSettings.Value;
    }

    [HttpPost("register")]
    public async Task<ActionResult> Register(RegisterUserViewModel registerUser)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState.Values.SelectMany(e => e.Errors).Select(e => e.ErrorMessage));

        var user = new IdentityUser
        {
            UserName = registerUser.Email,
            Email = registerUser.Email,
            EmailConfirmed = true
        };

        var result = await _userManager.CreateAsync(user, registerUser.Password);

        if(!result.Succeeded)
            return BadRequest(result.Errors);

        await _signInManager.SignInAsync(user, false);
        
        return Ok(GenerateJwtToken(user.Email));
    }

    [HttpPost("login")]
    public async Task<ActionResult> Login(LoginUserViewModel loginUser)
    {
        if(!ModelState.IsValid)
            return BadRequest(ModelState.Values.SelectMany(e => e.Errors).Select(e => e.ErrorMessage));

        var result = await _signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, false, true);
        
        if(result.Succeeded)
        {
            return Ok(GenerateJwtToken(loginUser.Email).Result);
        }

        if (result.IsLockedOut)
            return BadRequest("User is locked out temporarily");

        return BadRequest("Invalid user or password");
    }

    private async Task<LoginResponseViewModel> GenerateJwtToken(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        var claims = await _userManager.GetClaimsAsync(user);
        var userRoles = await _userManager.GetRolesAsync(user);

        claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
        claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
        claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, ToUnixEpochDate(DateTime.UtcNow).ToString()));
        claims.Add(new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64));

        foreach (var userRole in userRoles)
        {
            claims.Add(new Claim("role", userRole));
        }

        var identityClaims = new ClaimsIdentity();
        identityClaims.AddClaims(claims);
        
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
        var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _appSettings.Issuer,
            Audience = _appSettings.Audience,
            Subject = identityClaims,
            Expires = DateTime.UtcNow.AddHours(_appSettings.ExpirationInMinutes),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        });

        var encodedToken = tokenHandler.WriteToken(token);

        var response = new LoginResponseViewModel
        {
            AccessToken = encodedToken,
            ExpiresIn = TimeSpan.FromHours(_appSettings.ExpirationInMinutes).TotalSeconds
        };

        return response;
    }

    private static long ToUnixEpochDate(DateTime date)
    {
        return (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
    }
}


//Test controller
[Authorize]
public class UserController : MainController
{
    public readonly UserManager<IdentityUser> _userManager;

    public UserController(UserManager<IdentityUser> userManager)
    {
        _userManager = userManager;
    }

    [ClaimsAuthorize("admin", "read")]
    [HttpGet("user")]
    public async Task<ActionResult> GetUser()
    {
        var user = await _userManager.FindByEmailAsync("bianor.araujo@gmail.com");
        
        return Ok(user);
    }
}
