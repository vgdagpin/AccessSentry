using AccessSentry.Interfaces;

using Casbin;
using Casbin.Adapter.File;
using Casbin.Model;
using Casbin.Persist;

using Microsoft.Extensions.Caching.Memory;

using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AccessSentry.PermissionProviders.Casbin
{
    public class RBACPermissionProvider : BaseCasbinPermissionProvider
    {
        private readonly IPolicyProvider policyProvider;

        #region Properties
        public override CasbinModel Model => new CasbinModel
        {
            RequestDefinition = "r = role, resource, action",
            PolicyDefinition = "p = role, resource, action",
            PolicyEffect = "e = some(where (p.eft == allow))",
            Matchers = "m = r.role == p.role && r.resource == p.resource && r.action == p.action"
        };

        public override string Policy => policyProvider.GetPolicy(); 
        #endregion

        public RBACPermissionProvider(IPolicyProvider policyProvider)
        {
            this.policyProvider = policyProvider;
        }


        public override bool CanUseProvider(IAuthorizationContext authorizationContext)
            => authorizationContext is RBACAuthorizationContext;

        protected string[] GetRoles()
        {
            if (AuthorizationContext.User != null && AuthorizationContext.User is ClaimsPrincipal claimsPrincipal)
            {
                return claimsPrincipal.FindAll(ClaimTypes.Role).Select(a => a.Value).ToArray();
            }

            return Array.Empty<string>();
        }

        public override bool EvaluateContext()
        {
            var authContext = AuthorizationContext as RBACAuthorizationContext;

            if (authContext == null || authContext.Permissions == null || authContext.Permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            var enforcer = GetEnforcer();
            var roles = GetRoles();

            foreach (var permission in authContext.Permissions)
            {
                foreach (var role in roles)
                {
                    var result = enforcer.Enforce(role, permission.Resource, permission.Action);

                    if (result)
                    {
                        hasAny = true;
                        break;
                    }
                }

                if (hasAny)
                {
                    break;
                }
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
            var roles = GetRoles();

            foreach (var permission in authContext.Permissions)
            {
                foreach (var role in roles)
                {
                    var result = await enforcer.EnforceAsync(role, permission.Resource, permission.Action);

                    if (result)
                    {
                        hasAny = true;
                        break;
                    }
                }

                if (hasAny)
                {
                    break;
                }
            }

            return hasAny;
        }

        public class RBACAuthorizationContext : IAuthorizationContext
        {
            public IPrincipal User { get; }
            public Permission[] Permissions { get; }

            public RBACAuthorizationContext(IPrincipal principal, params Permission[] permissions)
            {
                User = principal;
                Permissions = permissions;
            }
        }
    }

}