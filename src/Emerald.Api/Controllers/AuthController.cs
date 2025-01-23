using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Emerald.Api.Extensions;
using Emerald.Api.Interfaces;
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
    public readonly IEmailSender _emailSender;

    public AuthController(SignInManager<IdentityUser> signInManager,
                          UserManager<IdentityUser> userManager,
                          IOptions<AppSettings> appSettings,
                          IEmailSender emailSender)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _appSettings = appSettings.Value;
        _emailSender = emailSender;
    }

    [HttpPost("register")]
    public async Task<ActionResult> Register(RegisterUserViewModel registerUser)
    {
        if (!ModelState.IsValid)
            return CustomResponse(ModelState);

        var user = new IdentityUser
        {
            UserName = registerUser.Email,
            Email = registerUser.Email,
            EmailConfirmed = !registerUser.SendEmailConfirmation
        };

        var createResult = await _userManager.CreateAsync(user, registerUser.Password);

        if(!createResult.Succeeded)
        {
            return CustomResponse(createResult);
        }

        if(registerUser.SendEmailConfirmation)
        {
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = Url.Action("ConfirmEmail", "Auth", new { userId = user.Id, code }, Request.Scheme);
            var emailTo = user.Email;
            var subject = "Confirm your email";

            await _emailSender.SendEmailAsync(emailTo, subject, callbackUrl!);
        }

        await _signInManager.SignInAsync(user, false);
        
        var data = GenerateJwtToken(user.Email).Result;

        return CustomResponse(data);
    }

    [HttpPost("login")]
    public async Task<ActionResult> Login(LoginUserViewModel loginUser)
    {
        if(!ModelState.IsValid)
            return CustomResponse(ModelState);

        var result = await _signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, false, true);
        
        if(result.Succeeded)
        {
            var data = GenerateJwtToken(loginUser.Email).Result;
            return CustomResponse(data);
        }

        return CustomResponse(result);
    }

    [Authorize]
    [HttpPost("reset-password")]
    public async Task<ActionResult> ResetPassword(ResetPasswordViewModel resetPassword)
    {
        if(!ModelState.IsValid)
            return CustomResponse(ModelState);

        var user = await _userManager.FindByEmailAsync(resetPassword.Email);

        if (user != null)
            await _userManager.ChangePasswordAsync(user, resetPassword.CurrentPassword, resetPassword.NewPassword);

        return CustomResponse("Password reseted successfully", true);
    }

    [HttpGet("confirm-email")]
    public async Task<ActionResult> ConfirmEmail(string userId, string code)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
            return CustomResponse("Invalid email verification", false);

        var user = await _userManager.FindByIdAsync(userId);

        if(user == null)
            return CustomResponse("Invalid email verification", false);
        
        var verificationResult = await _userManager.ConfirmEmailAsync(user, code);

        if (verificationResult.Succeeded)
            return CustomResponse("Email confirmed successfully", true);

        return CustomResponse(verificationResult);
    }

    [Authorize]
    [HttpGet("token-validation")]
    public async Task<ActionResult> TokenValidation()
    {
        return CustomResponse("Token is valid", true);
    }

    [HttpGet("send-email")]
    public async Task<ActionResult> SendEmail(UserRequestViewModel userRequest)
    {

        var user = await _userManager.FindByEmailAsync(userRequest.Email);

        if (user == null)
            return CustomResponse("User not found", false);

        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var callbackUrl = Url.Action("ConfirmEmail", "Auth", new { userId = user.Id, code }, Request.Scheme);
        var emailTo = user.Email;
        var subject = "Confirm your email";

        var result = await _emailSender.SendEmailAsync(emailTo!, subject, callbackUrl!);
        
        return CustomResponse(result ? "Email sent successfully" : "Error sending email", result);
    }

    [Authorize]
    [HttpPost("user")]
    public async Task<ActionResult> GetUser(UserRequestViewModel userRequest)
    {
        var user = await _userManager.FindByEmailAsync(userRequest.Email);

        if (user == null)
            return CustomResponse("User not found", false);

        return CustomResponse(user);
    }

    

    private async Task<LoginResponseViewModel> GenerateJwtToken(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        
        if (user == null)
            return null;

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
            ExpiresIn = TimeSpan.FromHours(_appSettings.ExpirationInMinutes).TotalMinutes,
            User = user
        };

        return response;
    }

    private static long ToUnixEpochDate(DateTime date)
    {
        return (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
    }
}
