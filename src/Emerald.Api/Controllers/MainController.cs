using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Emerald.Api.Controllers;

[ApiController]
public abstract class MainController : ControllerBase
{
    protected ActionResult CustomResponse(ModelStateDictionary modelState)
    {
        return BadRequest(new
        {
            success = false,
            errors = modelState.Values.SelectMany(e => e.Errors).Select(e => e.ErrorMessage)
        });
    }

    protected ActionResult CustomResponse(IdentityResult result)
    {
        return BadRequest(new
        {
            success = false,
            errors = result.Errors.Select(e => e.Description)
        });
    }

    protected ActionResult CustomResponse(object result = null)
    {
        return Ok(new
        {
            success = true,
            data = result
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
