using AccessSentry.Interfaces;

using Casbin;

using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

using static AccessSentry.PermissionProviders.Casbin.CasbinPermissionEvaluatorProvider;

namespace AccessSentry.PermissionProviders.Casbin
{
    public class CasbinPermissionEvaluatorProvider : BasePermissionEvaluatorProvider<CasbinPermissionAuthorizationContext>
    {
        #region Properties
        public new CasbinPermissionAuthorizationContext AuthorizationContext
        {
            get => (CasbinPermissionAuthorizationContext)base.AuthorizationContext;
            set => base.AuthorizationContext = value;
        }

        public override CasbinModel Model => new CasbinModel
        {
            RequestDefinition = "r = role, perm",
            PolicyDefinition = new[] { "p = role, perm" },
            PolicyEffect = "e = some(where (p.eft == allow))",
            Matchers = new[] { "m = r.role == p.role && keyMatch(r.perm, p.perm)" }
        };
        #endregion

        public override bool EvaluateContext()
        {
            if (AuthorizationContext.Permissions == null || AuthorizationContext.Permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            var subject = GetSubject(AuthorizationContext.User);
            var enforcer = GetEnforcer(subject);

            foreach (var permission in AuthorizationContext.Permissions)
            {
                if (!string.IsNullOrWhiteSpace(subject)
                    && enforcer.Enforce(subject, permission))
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

            var subject = GetSubject(AuthorizationContext.User);
            var enforcer = GetEnforcer(subject);

            foreach (var permission in AuthorizationContext.Permissions)
            {
                if (!string.IsNullOrWhiteSpace(subject) && await enforcer.EnforceAsync(subject, permission))
                {
                    hasAny = true;
                    break;
                }
            }

            return hasAny;
        }

        public override string GetPolicy(string? subject = null) =>
@"
p, Admin, Booking:CanRead  
p, Admin, Booking:CanWrite
p, Admin, Organization:CanCreate
";

        public class CasbinPermissionAuthorizationContext : IAuthorizationContext
        {
            public virtual string[] Permissions { get; set; } = null!;
            public IPrincipal User { get; }

            public CasbinPermissionAuthorizationContext(IPrincipal principal, params string[] permissions)
            {
                User = principal;
                Permissions = permissions;
            }
        }
    }

}
