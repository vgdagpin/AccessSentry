﻿using AccessSentry.AuthorizationAttributes;
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
        public virtual string SuperAdminRole => "SuperAdmin";

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

        protected virtual bool IsSuperAdmin(IPrincipal principal) => principal.IsInRole(SuperAdminRole);

        protected virtual string ResolveRole(IPolicyContext policyContext)
        {
            return policyContext.Policy;
        }

        public virtual bool EvaluateContext()
        {
            if (PolicyContext == null
                || PolicyContext.User == null
                || string.IsNullOrWhiteSpace(PolicyContext.Policy))
            {
                return false;
            }

            if (IsSuperAdmin(PolicyContext.User))
            {
                return true;
            }

            var subject = GetSubject(PolicyContext.User);
            var enforcer = p_PolicyProvider.GetEnforcer(subject);
            var userRoles = enforcer.GetImplicitRolesForUser(subject);
            var role = ResolveRole(PolicyContext);

            return userRoles.Contains(role, StringComparer.OrdinalIgnoreCase);
        }

        public virtual Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default)
        {
            if (PolicyContext == null
                || PolicyContext.User == null
                || string.IsNullOrWhiteSpace(PolicyContext.Policy))
            {
                return Task.FromResult(false);
            }

            if (IsSuperAdmin(PolicyContext.User))
            {
                return Task.FromResult(true);
            }

            var subject = GetSubject(PolicyContext.User);
            var enforcer = p_PolicyProvider.GetEnforcer(subject);
            var userRoles = enforcer.GetImplicitRolesForUser(subject);
            var role = ResolveRole(PolicyContext);

            return Task.FromResult(userRoles.Contains(role, StringComparer.OrdinalIgnoreCase));
        }

        public virtual string? GetSubject(IPrincipal principal)
        {
            if (principal == null)
            {
                return null;
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

            return null;
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
