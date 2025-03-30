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
        #region Properties
        public virtual string SuperAdminRole => "SuperAdmin";

        public new RBACAuthorizationContext AuthorizationContext
        {
            get => (RBACAuthorizationContext)base.AuthorizationContext;
            set => base.AuthorizationContext = value;
        }
        #endregion

        public RBACPermissionEvaluatorProvider(IPolicyProvider policyProvider) 
            : base(policyProvider)
        {

        }

        protected virtual bool IsSuperAdmin(IPrincipal principal) => principal.IsInRole(SuperAdminRole);

        protected virtual string TranslateResource(Permission permission) => permission.Resource;

        public override bool EvaluateContext()
        {
            if (AuthorizationContext.Permissions == null || AuthorizationContext.Permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            if (IsSuperAdmin(AuthorizationContext.User))
            {
                return true;
            }

            var subject = GetSubject(AuthorizationContext.User);
            var enforcer = policyProvider.GetEnforcer(subject);

            foreach (var permission in AuthorizationContext.Permissions)
            {
                var resource = TranslateResource(permission);

                if (enforcer.Enforce(subject, resource, permission.Action))
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

            if (IsSuperAdmin(AuthorizationContext.User))
            {
                return true;
            }

            var subject = GetSubject(AuthorizationContext.User);
            var enforcer = policyProvider.GetEnforcer(subject);

            foreach (var permission in AuthorizationContext.Permissions)
            {
                var resource = TranslateResource(permission);

                if (await enforcer.EnforceAsync(subject, resource, permission.Action))
                {
                    hasAny = true;
                    break;
                }
            }

            return hasAny;
        }

        public class RBACAuthorizationContext : IAuthorizationContext
        {
            public IPrincipal User { get; }
            public Permission[]? Permissions { get; }

            public RBACAuthorizationContext(IPrincipal subject)
            {
                User = subject;
            }

            public RBACAuthorizationContext(IPrincipal subject, params Permission[] permissions)
            {
                User = subject;
                Permissions = permissions;
            }
        }
    }

}