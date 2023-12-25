using AccessSentry.Interfaces;

using Casbin;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AccessSentry.PermissionProviders.Casbin
{
    public abstract class BasePermissionEvaluatorProvider<T> : IPermissionEvaluator where T : IAuthorizationContext
    {
        protected readonly IPolicyProvider policyProvider;

        public virtual IAuthorizationContext AuthorizationContext { get; set; } = null!;

        public BasePermissionEvaluatorProvider(IPolicyProvider policyProvider)
        {
            this.policyProvider = policyProvider;
        }

        public virtual bool CanUseEvaluator(IAuthorizationContext authorizationContext) => authorizationContext is T;

        public abstract bool EvaluateContext();

        public abstract Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default);

        public virtual string GetSubject(IPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (principal is ClaimsPrincipal claimsPrincipal)
            {
                var nameClaim = claimsPrincipal.FindFirst(ClaimTypes.Name);

                if (nameClaim == null)
                {
                    nameClaim = claimsPrincipal.FindFirst(ClaimTypes.NameIdentifier);
                }

                if (nameClaim != null)
                {
                    if (!string.IsNullOrEmpty(nameClaim.Value))
                    {
                        return nameClaim.Value;
                    }
                }
            }

            throw new ArgumentNullException("No name found from principal");
        }

        public virtual IEnumerable<UserPermission> GetUserPermissions()
        {
            var subject = GetSubject(AuthorizationContext.User);
            var enforcer = policyProvider.GetEnforcer(subject);

            var userPermissions = enforcer.GetImplicitPermissionsForUser(subject);

            UserPermission FormatPerm(IEnumerable<string> perm)
            {
                var arr = perm.ToArray();

                return new UserPermission
                {
                    Source = arr[0],
                    Resource = arr[1],
                    Action = arr[2],
                    Allow = arr[3] == "allow"
                };
            }

            return userPermissions.Select(FormatPerm);
        }
    }

    public class CasbinModel
    {
        public string RequestDefinition { get; set; } = null!;
        public string[] PolicyDefinition { get; set; } = null!;
        public string[]? RoleDefinition { get; set; }
        public string PolicyEffect { get; set; } = null!;
        public string[] Matchers { get; set; } = null!;

        public override string ToString()
        {
            var sb = new StringBuilder();

            sb.AppendLine("[request_definition]");
            sb.AppendLine(RequestDefinition);
            sb.AppendLine();
            sb.AppendLine("[policy_definition]");
            foreach (var policyDef in PolicyDefinition)
            {
                sb.AppendLine(policyDef);
            }

            if (RoleDefinition != null && RoleDefinition.Length > 0)
            {
                sb.AppendLine();
                sb.AppendLine("[role_definition]");

                for (int i = 0; i < RoleDefinition.Length; i++)
                {
                    sb.AppendLine(RoleDefinition[i]);
                }
            }

            sb.AppendLine();
            sb.AppendLine("[policy_effect]");
            sb.AppendLine(PolicyEffect);
            sb.AppendLine();
            sb.AppendLine("[matchers]");
            foreach (var matcher in Matchers)
            {
                sb.AppendLine(matcher);
            }

            return sb.ToString();
        }
    }
}
