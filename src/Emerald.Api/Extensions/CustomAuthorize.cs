using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Emerald.Api.Extensions;

public class CustomAuthorization
{
    public static bool UserClaimsValidation(HttpContext context, string claimName, string claimValue)
    {
        if (context.User.Identity == null)
            throw new ArgumentNullException(nameof(context.User.Identity), "User cannot be null");

        return context.User.Identity.IsAuthenticated && context.User.Claims.Any(c => c.Type == claimName && c.Value.Contains(claimValue));
    }

}

public class ClaimsAuthorizeAttribute : TypeFilterAttribute
{
    public ClaimsAuthorizeAttribute(string claimName, string claimValue) : base(typeof(ClaimFilter))
    {
        Arguments = [ new Claim(claimName, claimValue) ];
    }
}

public class ClaimFilter : IAuthorizationFilter
{
    private readonly Claim _claim;

    public ClaimFilter(Claim claim)
    {
        _claim = claim;
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (context.HttpContext.User.Identity == null)
            throw new ArgumentNullException(nameof(context.HttpContext.User.Identity), "User cannot be null");

        if (!context.HttpContext.User.Identity.IsAuthenticated)
        {
            context.Result = new StatusCodeResult(401);
            return;
        }

        if (!CustomAuthorization.UserClaimsValidation(context.HttpContext, _claim.Type, _claim.Value))
            context.Result = new StatusCodeResult(403);
    }
}