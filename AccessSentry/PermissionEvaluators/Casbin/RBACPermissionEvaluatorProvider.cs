using AccessSentry.Interfaces;

using Casbin;

using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

using static AccessSentry.PermissionProviders.Casbin.RBACPermissionEvaluatorProvider;

namespace AccessSentry.PermissionProviders.Casbin
{
    public class RBACPermissionEvaluatorProvider : BasePermissionEvaluatorProvider<RBACAuthorizationContext>
    {
        private readonly IPolicyProvider policyProvider;

        #region Properties
        public virtual string SuperAdminRole => "r::SuperAdmin";

        public override CasbinModel Model => new CasbinModel
        {
            RequestDefinition = "r = sub, obj, act",
            PolicyDefinition = new[] { "p = sub, obj, act, eft" },
            RoleDefinition = new[] { "g = _, _" },
            PolicyEffect = "e = some(where (p.eft == allow)) && !some(where (p.eft == deny))",
            Matchers = new[] { $"m = g(p.sub, r.sub) && r.obj == p.obj && r.act == p.act" }
        };

        public new RBACAuthorizationContext AuthorizationContext
        {
            get => (RBACAuthorizationContext)base.AuthorizationContext;
            set => base.AuthorizationContext = value;
        }
        #endregion

        public RBACPermissionEvaluatorProvider(IPolicyProvider policyProvider)
        {
            this.policyProvider = policyProvider;
        }

        protected virtual bool IsSuperAdmin()
        {
            if (!string.IsNullOrWhiteSpace(SuperAdminRole) && GetSubject(AuthorizationContext.User) == SuperAdminRole)
            {
                return true;
            }

            return false;
        }

        protected virtual string TranslateResource(Permission permission)
        {
            return permission.Resource;
        }

        public override bool EvaluateContext()
        {
            if (AuthorizationContext.Permissions == null || AuthorizationContext.Permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            if (IsSuperAdmin())
            {
                return true;
            }

            var subject = GetSubject(AuthorizationContext.User);
            var enforcer = GetEnforcer(subject);

            foreach (var permission in AuthorizationContext.Permissions)
            {
                // check for user first, then roles
                if (!string.IsNullOrWhiteSpace(subject)
                    && enforcer.Enforce(subject, TranslateResource(permission), permission.Action))
                {
                    hasAny = true;
                    break;
                }
            }

            return hasAny;
        }

        public override async Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default)
        {
            if (AuthorizationContext.Permissions == null || AuthorizationContext.Permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            if (IsSuperAdmin())
            {
                return true;
            }

            var subject = GetSubject(AuthorizationContext.User);
            var enforcer = GetEnforcer(subject);

            foreach (var permission in AuthorizationContext.Permissions)
            {
                if (!string.IsNullOrWhiteSpace(subject)
                   && await enforcer.EnforceAsync(subject, TranslateResource(permission), permission.Action))
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