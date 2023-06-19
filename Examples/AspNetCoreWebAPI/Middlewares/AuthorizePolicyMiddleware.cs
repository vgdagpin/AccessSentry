using AccessSentry.AuthorizationAttributes;
using AccessSentry.Interfaces;

using Microsoft.AspNetCore.Authorization;

namespace AspNetCoreWebAPI.Middlewares;

public class AuthorizePolicyMiddleware
{
    private readonly RequestDelegate next;

    public AuthorizePolicyMiddleware(RequestDelegate next)
    {
        this.next = next;
    }

    public async Task Invoke(HttpContext context, IPolicyEvaluatorFactory policyEvaluatorFactory)
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

        var attrs = endpoint?.Metadata.GetOrderedMetadata<AuthorizePolicyAttribute>();

        if (attrs == null || attrs.Count == 0 || !attrs.Any(a => a is AuthorizePolicyAttribute))
        {
            await next(context);
            return;
        }
        var hasAll = true;

        foreach (var attribute in attrs)
        {
            if (attribute is AuthorizePolicyAttribute attr1)
            {
                foreach (var policyEvaluator in policyEvaluatorFactory.GetPolicyEvaluators(attr1))
                {
                    if (!await policyEvaluator.EvaluateAsync())
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
