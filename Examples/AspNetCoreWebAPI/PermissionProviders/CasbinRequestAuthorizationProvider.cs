using AccessSentry.AuthorizationAttributes;
using AccessSentry.Interfaces;
using AccessSentry.PermissionProviders.Casbin;

using Microsoft.AspNetCore.Mvc;

using System.Security.Claims;
using System.Security.Principal;

namespace AspNetCoreWebAPI.PermissionProviders;


public class CasbinRequestAuthorizationProvider : BaseCasbinPermissionProvider
{
    #region Properties
    public override CasbinModel Model => new CasbinModel
    {
        RequestDefinition = "r = sub, obj, act",
        PolicyDefinition = "p = sub, obj, act",
        PolicyEffect = "e = some(where (p.eft == allow))",
        Matchers = "m = r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)"
    };

    public override string Policy =>
@"
p, Vincent, PermissionSample/PermissionViaMethod_HasAny, GET
"; 
    #endregion

    public override bool CanUseProvider(IAuthorizationContext authorizationContext)
        => authorizationContext is CasbinRequestAuthorizationContext;

    public override bool EvaluateContext()
    {
        throw new NotImplementedException();
    }

    public override Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
    }

    public class CasbinRequestAuthorizationContext : IAuthorizationContext
    {
        public virtual Endpoint? EndPoint { get; set; }
        public virtual HttpContext HttpContext { get; set; } = null!;
        public virtual AuthorizePermissionAttribute? AuthAttributes { get; set; }
        public IPrincipal User { get; }

        public CasbinRequestAuthorizationContext(IPrincipal principal)
        {
            User = principal;
        }

        public virtual ClaimsPrincipal GetClaimsPrincipal()
        {
            return HttpContext.User;
        }

        public virtual string? GetUser()
        {
            return HttpContext.User.FindFirst(ClaimTypes.Name)?.Value;
        }

        public virtual string GetEndPoint()
        {
            if (EndPoint is null)
            {
                return string.Empty;
            }

            if (EndPoint is RouteEndpoint routeEndPoint)
            {
                var result = routeEndPoint.RoutePattern.RawText;

                if (string.IsNullOrWhiteSpace(result))
                {
                    return string.Empty;
                }

                return result;
            }

            return EndPoint.DisplayName ?? string.Empty;
        }

        public virtual string GetHttpMethod()
        {
            if (EndPoint?.Metadata.GetMetadata<HttpPostAttribute>() is not null)
            {
                return "POST";
            }

            if (EndPoint?.Metadata.GetMetadata<HttpPutAttribute>() is not null)
            {
                return "PUT";
            }

            if (EndPoint?.Metadata.GetMetadata<HttpDeleteAttribute>() is not null)
            {
                return "DELETE";
            }

            return "GET";
        }
    }
}
