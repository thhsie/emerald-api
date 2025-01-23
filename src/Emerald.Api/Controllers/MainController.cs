using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Emerald.Api.Controllers;

[ApiController]
public abstract class MainController : ControllerBase
{
    protected ActionResult CustomResponse(object data, bool success = true)
    {
        var response = new
        {
            Success = success,
            Data = data
        };

        if(!success)
            return BadRequest(response);

        return Ok(response);
    }

    protected ActionResult CustomResponse(string message, bool success)
    {
        if(!success)
            return BadRequest(new
            {
                Success = false,
                Errors = new List<string> { message }
            });

        return Ok(new 
            {
                Success = true,
                Message = message
            });
    }

    protected ActionResult CustomResponse(ModelStateDictionary modelState)
    {
        return BadRequest(new
        {
            Success = false,
            Errors = modelState.Values.SelectMany(e => e.Errors).Select(e => e.ErrorMessage)
        });
    }

    protected ActionResult CustomResponse(IdentityResult result)
    {
        return BadRequest(new
        {
            Success = false,
            Errors = result.Errors.Select(e => e.Description)
        });
    }

    protected ActionResult CustomResponse(Microsoft.AspNetCore.Identity.SignInResult result)
    {
        object data = null;

        if (result.IsLockedOut)
        {
            data = new
            {
                Success = false,
                Errors = new List<string> { "User is locked out temporarily" }
            };
        }

        if (!result.Succeeded)
        {
            data = new
            {
                Success = false,
                Errors = new List<string> { "Invalid user or password" }
            };
        }

        return BadRequest(data);
    }
}
