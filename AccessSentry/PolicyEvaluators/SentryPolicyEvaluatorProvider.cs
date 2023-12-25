using AccessSentry.AuthorizationAttributes;
using AccessSentry.Interfaces;

using Casbin;

using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace AccessSentry.PolicyEvaluators
{
    public class SentryPolicyEvaluatorProvider : IPolicyEvaluator
    {
        protected IPolicyContext? PolicyContext;
        private readonly IPolicyProvider p_PolicyProvider;

        public SentryPolicyEvaluatorProvider(IPolicyProvider policyProvider)
        {
            p_PolicyProvider = policyProvider;
        }

        public virtual bool CanUseEvaluator(IPolicyContext policyContext)
        {
            if (policyContext is SentryPolicyAttribute policyCtx)
            {
                PolicyContext = policyCtx;

                return true;
            }

            return false;
        }

        public virtual bool EvaluateContext()
        {
            if (PolicyContext == null
                || PolicyContext.User == null
                || string.IsNullOrWhiteSpace(PolicyContext.Policy))
            {
                return false;
            }

            var subject = GetSubject(PolicyContext.User);
            var enforcer = p_PolicyProvider.GetEnforcer(subject);
            var userRoles = enforcer.GetImplicitRolesForUser(subject);

            return userRoles.Contains(PolicyContext.Policy);
        }

        public virtual Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default)
        {
            if (PolicyContext == null
                || PolicyContext.User == null
                || string.IsNullOrWhiteSpace(PolicyContext.Policy))
            {
                return Task.FromResult(false);
            }

            var subject = GetSubject(PolicyContext.User);
            var enforcer = p_PolicyProvider.GetEnforcer(subject);
            var userRoles = enforcer.GetImplicitRolesForUser(subject);

            return Task.FromResult(userRoles.Contains(PolicyContext.Policy));
        }

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

        public virtual string[] GetUserMemberships()
        {
            if (PolicyContext == null)
            {
                return Array.Empty<string>();
            }

            var subject = GetSubject(PolicyContext.User);
            var enforcer = p_PolicyProvider.GetEnforcer(subject);

            return enforcer.GetImplicitRolesForUser(subject)
                .ToArray();
        }
    }
}
