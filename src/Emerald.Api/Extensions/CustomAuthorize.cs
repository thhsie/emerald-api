using Microsoft.AspNetCore.Authorization;

namespace Emerald.Api.Extensions;

public class CustomAuthorization
{
    public static bool UserClaimsValidation(AuthorizationHandlerContext context, string claimName, string claimValue)
    {
        if (context.User.Identity == null)
            throw new ArgumentNullException(nameof(context.User.Identity), "User cannot be null");

        return context.User.Identity.IsAuthenticated && context.User.Claims.Any(c => c.Type == claimName && c.Value.Contains(claimValue));
    }

}
