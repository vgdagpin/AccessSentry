using AccessSentry.Interfaces;

using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;

using static AccessSentry.PermissionProviders.Casbin.RBACPermissionEvaluatorProvider;

namespace AccessSentry
{
    public class AccessSentryAuthorizationService : IAccessSentryAuthorizationService
    {
        public IPermissionEvaluatorFactory PermissionEvaluatorFactory { get; }
        public IPolicyEvaluatorFactory PolicyEvaluatorFactory { get; }

        public AccessSentryAuthorizationService
            (
                IPermissionEvaluatorFactory permissionEvaluatorFactory,
                IPolicyEvaluatorFactory policyEvaluatorFactory
            )
        {
            PermissionEvaluatorFactory = permissionEvaluatorFactory;
            PolicyEvaluatorFactory = policyEvaluatorFactory;
        }

        protected virtual Permission[] GetPermissions(params string[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return new Permission[0];
            }

            var list = new List<Permission>();

            foreach (var permission in permissions)
            {
                var p = Permission.Parse(permission);

                if (p != null)
                {
                    list.Add(p);
                }
            }

            return list.ToArray();
        }

        public bool EvaluatePermission(IPrincipal principal, Enums.Has has, params string[] permissions)
        {
            return has == Enums.Has.Any 
                ? HasAnyPermission(principal, permissions) 
                : HasAllPermission(principal, permissions);
        }

        public Task<bool> EvaluatePermissionAsync(IPrincipal principal, Enums.Has has, params string[] permissions)
        {
            return has == Enums.Has.Any
                ? HasAnyPermissionAsync(principal, permissions)
                : HasAllPermissionAsync(principal, permissions);
        }

        public bool EvaluatePermission(IPrincipal principal, Enums.Has has, params Permission[] permissions)
        {
            return has == Enums.Has.Any
                ? HasAnyPermission(principal, permissions)
                : HasAllPermission(principal, permissions);
        }

        public Task<bool> EvaluatePermissionAsync(IPrincipal principal, Enums.Has has, params Permission[] permissions)
        {
            return has == Enums.Has.Any
                ? HasAnyPermissionAsync(principal, permissions)
                : HasAllPermissionAsync(principal, permissions);
        }

        public bool EvaluatePolicy(IPrincipal principal, Enums.Has has, params string[] policy)
        {
            return has == Enums.Has.Any
                ? HasAnyPolicy(principal, policy)
                : HasAllPolicy(principal, policy);
        }

        public Task<bool> EvaluatePolicyAsync(IPrincipal principal, Enums.Has has, params string[] policy)
        {
            return has == Enums.Has.Any
                ? HasAnyPolicyAsync(principal, policy)
                : HasAllPolicyAsync(principal, policy);
        }

        #region HasAnyPolicy
        protected virtual bool HasAnyPolicy(IPrincipal principal, params string[] policy)
        {
            var hasAny = false;

            foreach (var policyEvaluator in PolicyEvaluatorFactory.GetPolicyEvaluators(new PolicyContext(principal)))
            {
                if (policyEvaluator.EvaluateContext())
                {
                    hasAny = true;
                    break;
                }
            }

            return hasAny;
        }

        protected virtual async Task<bool> HasAnyPolicyAsync(IPrincipal principal, params string[] policy)
        {
            var hasAny = false;

            foreach (var policyEvaluator in PolicyEvaluatorFactory.GetPolicyEvaluators(new PolicyContext(principal)))
            {
                if (await policyEvaluator.EvaluateContextAsync())
                {
                    hasAny = true;
                    break;
                }
            }

            return hasAny;
        }
        #endregion

        #region HasAllPolicy
        protected virtual bool HasAllPolicy(IPrincipal principal, params string[] policy)
        {
            var hasAll = true;

            foreach (var policyEvaluator in PolicyEvaluatorFactory.GetPolicyEvaluators(new PolicyContext(principal)))
            {
                if (!policyEvaluator.EvaluateContext())
                {
                    hasAll = false;
                    break;
                }
            }

            return hasAll;
        }

        protected virtual async Task<bool> HasAllPolicyAsync(IPrincipal principal, params string[] policy)
        {
            var hasAll = true;

            foreach (var policyEvaluator in PolicyEvaluatorFactory.GetPolicyEvaluators(new PolicyContext(principal)))
            {
                if (!await policyEvaluator.EvaluateContextAsync())
                {
                    hasAll = false;
                    break;
                }
            }

            return hasAll;
        } 
        #endregion

        #region HasAllPermission
        protected virtual bool HasAllPermission(IPrincipal principal, params string[] permissions) => HasAllPermission(principal, GetPermissions(permissions));

        protected virtual Task<bool> HasAllPermissionAsync(IPrincipal principal, params string[] permissions) => HasAllPermissionAsync(principal, GetPermissions(permissions));

        protected virtual bool HasAllPermission(IPrincipal principal, params Permission[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return false;
            }

            var hasAll = true;

            foreach (var permissionEvaluator in PermissionEvaluatorFactory.GetPermissionEvaluators(new RBACAuthorizationContext(principal, permissions)))
            {
                if (!permissionEvaluator.EvaluateContext())
                {
                    hasAll = false;
                    break;
                }
            }

            return hasAll;
        }

        protected virtual async Task<bool> HasAllPermissionAsync(IPrincipal principal, params Permission[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return false;
            }

            var hasAll = true;

            foreach (var permissionEvaluator in PermissionEvaluatorFactory.GetPermissionEvaluators(new RBACAuthorizationContext(principal, permissions)))
            {
                if (!await permissionEvaluator.EvaluateContextAsync())
                {
                    hasAll = false;
                    break;
                }
            }

            return hasAll;
        }
        #endregion

        #region HasAnyPermission
        protected virtual bool HasAnyPermission(IPrincipal principal, params string[] permissions) => HasAnyPermission(principal, GetPermissions(permissions));

        protected virtual Task<bool> HasAnyPermissionAsync(IPrincipal principal, params string[] permissions) => HasAnyPermissionAsync(principal, GetPermissions(permissions));

        protected virtual bool HasAnyPermission(IPrincipal principal, params Permission[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            foreach (var permissionEvaluator in PermissionEvaluatorFactory.GetPermissionEvaluators(new RBACAuthorizationContext(principal, permissions)))
            {
                if (permissionEvaluator.EvaluateContext())
                {
                    hasAny = true;
                    break;
                }
            }

            return hasAny;
        }

        protected virtual async Task<bool> HasAnyPermissionAsync(IPrincipal principal, params Permission[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            foreach (var permissionEvaluator in PermissionEvaluatorFactory.GetPermissionEvaluators(new RBACAuthorizationContext(principal, permissions)))
            {
                if (await permissionEvaluator.EvaluateContextAsync())
                {
                    hasAny = true;
                    break;
                }
            }

            return hasAny;
        }

        public string[] GetUserMemberships(IPrincipal principal)
        {
            var result = new List<string>();

            foreach (var policyEvaluator in PolicyEvaluatorFactory.GetPolicyEvaluators(new PolicyContext(principal)))
            {
                result.AddRange(policyEvaluator.GetUserMemberships());
            }

            return result.Distinct().ToArray();
        }

        public IEnumerable<RBACPolicy> GetUserPermissions(IPrincipal principal)
        {
            var result = new List<RBACPolicy>();
            var authContext = new RBACAuthorizationContext(principal);

            foreach (var permissionEvaluator in PermissionEvaluatorFactory.GetPermissionEvaluators(authContext))
            {
                result.AddRange(permissionEvaluator.GetUserPermissions());
            }

            return result;
        }
        #endregion
    }
}
