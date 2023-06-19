using AccessSentry.AuthorizationAttributes;
using AccessSentry.Interfaces;

using Microsoft.AspNetCore.Authorization;

using static AspNetCoreWebAPI.PermissionProviders.CasbinRequestAuthorizationProvider;

namespace AspNetCoreWebAPI.Middlewares;

public class AuthorizePermissionMiddleware
{
    private readonly RequestDelegate next;

    public AuthorizePermissionMiddleware(RequestDelegate next)
    {
        this.next = next;
    }

    public async Task Invoke(HttpContext context, IPermissionProviderFactory permissionProviderFactory)
    {
        if (context == null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        var endpoint = context.GetEndpoint();

        // if allow anonymous, go on..
        if (endpoint?.Metadata.GetMetadata<IAllowAnonymous>() is not null)
        {
            await next(context);
            return;
        }

        var attrs = endpoint?.Metadata.GetOrderedMetadata<AuthorizePermissionAttribute>();

        if (attrs == null || attrs.Count == 0 || !attrs.Any(a => a is AuthorizePermissionAttribute)) 
        {
            await next(context);
            return;
        }
        var hasAll = true;

        foreach (var attribute in attrs)
        {
            if (attribute is AuthorizePermissionAttribute attr1)
            {
                var authContext = new CasbinRequestAuthorizationContext(context.User)
                {
                    HttpContext = context,
                    EndPoint = endpoint,
                    AuthAttributes = attr1
                };

                foreach (var permissionProvider in permissionProviderFactory.GetPermissionProviders(authContext))
                {
                    if (!await permissionProvider.EvaluateContextAsync())
                    {
                        hasAll = false;
                        break;
                    }
                }
            }

            if (!hasAll)
            {
                break;
            }
        }

        if (hasAll)
        {
            await next(context);
            return;
        }

        throw new UnauthorizedAccessException();
    }
}