using AccessSentry.Interfaces;

using Casbin;

using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace AccessSentry.PermissionProviders.Casbin
{
    public class RBACPermissionProvider : BaseCasbinPermissionProvider
    {
        private readonly IPolicyProvider policyProvider;

        public virtual string SuperAdminRole => "r::SuperAdmin";

        #region Properties
        public override CasbinModel Model => new CasbinModel
        {
            RequestDefinition = "r = sub, obj, act",
            PolicyDefinition = new[] { "p = sub, obj, act, eft" },
            RoleDefinition = new[] { "g = _, _" },
            PolicyEffect = "e = some(where (p.eft == allow)) && !some(where (p.eft == deny))",
            Matchers = new[] { $"m = g(p.sub, r.sub) && r.obj == p.obj && r.act == p.act" }
        };
        #endregion

        public RBACPermissionProvider(IPolicyProvider policyProvider)
        {
            this.policyProvider = policyProvider;
        }

        protected virtual bool IsSuperAdmin(IAuthorizationContext authorizationContext)
        {
            var subject = GetSubject(authorizationContext.User);

            if (!string.IsNullOrWhiteSpace(SuperAdminRole) && subject == SuperAdminRole)
            {
                return true;
            }

            return false;
        }

        public override bool CanUseProvider(IAuthorizationContext authorizationContext) => authorizationContext is RBACAuthorizationContext;

        public override bool EvaluateContext()
        {
            var authContext = AuthorizationContext as RBACAuthorizationContext;

            if (authContext == null || authContext.Permissions == null || authContext.Permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            if (IsSuperAdmin(authContext))
            {
                return true;
            }

            var subject = GetSubject(authContext.User);

            var enforcer = GetEnforcer(subject);

            foreach (var permission in authContext.Permissions)
            {
                // check for user first, then roles
                if (!string.IsNullOrWhiteSpace(subject)
                    && enforcer.Enforce(subject, permission.Resource, permission.Action))
                {
                    hasAny = true;
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

            if (IsSuperAdmin(authContext))
            {
                return true;
            }

            var subject = GetSubject(authContext.User);
            var enforcer = GetEnforcer(subject);

            foreach (var permission in authContext.Permissions)
            {
                if (!string.IsNullOrWhiteSpace(subject)
                   && await enforcer.EnforceAsync(subject, permission.Resource, permission.Action))
                {
                    hasAny = true;
                    break;
                }
            }

            return hasAny;
        }

        public override string GetPolicy(string? subject = null) => policyProvider.GetPolicy(subject);

        public class RBACAuthorizationContext : IAuthorizationContext
        {
            public IPrincipal User { get; }
            public Permission[] Permissions { get; }

            public RBACAuthorizationContext(IPrincipal subject, params Permission[] permissions)
            {
                User = subject;
                Permissions = permissions;
            }
        }
    }

}