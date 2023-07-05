using AccessSentry.Interfaces;

using Casbin;

using System.Threading;
using System.Threading.Tasks;

namespace AccessSentry.PermissionProviders.Casbin
{
    public class RBACPermissionProvider : BaseCasbinPermissionProvider
    {
        private readonly IPolicyProvider policyProvider;

        protected virtual string SuperAdminRole => "SuperAdmin";

        #region Properties
        public override CasbinModel Model => new CasbinModel
        {
            RequestDefinition = "r = sub, obj, act",
            PolicyDefinition = "p = sub, obj, act, eft",
            RoleDefinition = new[] { "g = _, _" },
            PolicyEffect = "e = some(where (p.eft == allow)) && !some(where (p.eft == deny))",
            Matchers = $"m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || p.sub == {SuperAdminRole}"
        };

        public override string Policy => policyProvider.GetPolicy(); 
        #endregion

        public RBACPermissionProvider(IPolicyProvider policyProvider)
        {
            this.policyProvider = policyProvider;
        }


        public override bool CanUseProvider(IAuthorizationContext authorizationContext)
            => authorizationContext is RBACAuthorizationContext;

        //protected string[] GetRoles()
        //{
        //    if (AuthorizationContext.User != null && AuthorizationContext.User is ClaimsPrincipal claimsPrincipal)
        //    {
        //        return claimsPrincipal.FindAll(ClaimTypes.Role).Select(a => a.Value).ToArray();
        //    }

        //    return Array.Empty<string>();
        //}

        //protected string? GetName()
        //{
        //    if (AuthorizationContext.User != null && AuthorizationContext.User is ClaimsPrincipal claimsPrincipal)
        //    {
        //        return claimsPrincipal.FindFirst(ClaimTypes.Name)?.Value;
        //    }

        //    return null;
        //}

        public override bool EvaluateContext()
        {
            var authContext = AuthorizationContext as RBACAuthorizationContext;

            if (authContext == null || authContext.Permissions == null || authContext.Permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            var enforcer = GetEnforcer();
            //var roles = GetRoles();

            foreach (var permission in authContext.Permissions)
            {
                //var user = GetName();

                // check for user first, then roles
                if (!string.IsNullOrWhiteSpace(authContext.User)
                    && enforcer.Enforce(authContext.User, permission.Resource, permission.Action))
                {
                    hasAny = true;
                    break;
                }
                //else
                //{
                //    foreach (var role in roles)
                //    {
                //        var result = enforcer.Enforce(role, permission.Resource, permission.Action);

                //        if (result)
                //        {
                //            hasAny = true;
                //            break;
                //        }
                //    }
                //}

                //if (hasAny)
                //{
                //    break;
                //}
            }

            return hasAny;
        }

        public override async Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default)
        {
            var authContext = AuthorizationContext as RBACAuthorizationContext;

            if (authContext == null || authContext.Permissions == null || authContext.Permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            var enforcer = GetEnforcer();
            //var roles = GetRoles();

            foreach (var permission in authContext.Permissions)
            {
                if (!string.IsNullOrWhiteSpace(authContext.User)
                   && enforcer.Enforce(authContext.User, permission.Resource, permission.Action))
                {
                    hasAny = true;
                    break;
                }

                //foreach (var role in roles)
                //{
                //    var result = await enforcer.EnforceAsync(role, permission.Resource, permission.Action);

                //    if (result)
                //    {
                //        hasAny = true;
                //        break;
                //    }
                //}

                //if (hasAny)
                //{
                //    break;
                //}
            }

            return hasAny;
        }

        public class RBACAuthorizationContext : IAuthorizationContext
        {
            public string User { get; }
            public Permission[] Permissions { get; }

            public RBACAuthorizationContext(string subject, params Permission[] permissions)
            {
                User = subject;
                Permissions = permissions;
            }
        }
    }

}