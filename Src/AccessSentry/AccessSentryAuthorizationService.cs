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

        public bool EvaluatePermission(Enums.Has has, params IAuthorizationContext[] permissions)
        {
            return has == Enums.Has.Any 
                ? HasAnyPermission(permissions) 
                : HasAllPermission(permissions);
        }

        public Task<bool> EvaluatePermissionAsync(Enums.Has has, params IAuthorizationContext[] permissions)
        {
            return has == Enums.Has.Any
                ? HasAnyPermissionAsync(permissions)
                : HasAllPermissionAsync(permissions);
        }

        public bool EvaluatePolicy(Enums.Has has, params IPolicyContext[] policy)
        {
            return has == Enums.Has.Any
                ? HasAnyPolicy(policy)
                : HasAllPolicy(policy);
        }

        public Task<bool> EvaluatePolicyAsync(Enums.Has has, params IPolicyContext[] policy)
        {
            return has == Enums.Has.Any
                ? HasAnyPolicyAsync(policy)
                : HasAllPolicyAsync(policy);
        }

        #region HasAnyPolicy
        protected virtual bool HasAnyPolicy(params IPolicyContext[] policy)
        {
            var hasAny = false;

            if (policy == null || policy.Length == 0)
            {
                return false;
            }

            foreach (var p in policy)
            {
                foreach (var policyEvaluator in PolicyEvaluatorFactory.GetPolicyEvaluators(p))
                {
                    if (policyEvaluator.EvaluateContext())
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

        protected virtual async Task<bool> HasAnyPolicyAsync(params IPolicyContext[] policy)
        {
            var hasAny = false;

            if (policy == null || policy.Length == 0)
            {
                return false;
            }

            foreach (var p in policy)
            {
                foreach (var policyEvaluator in PolicyEvaluatorFactory.GetPolicyEvaluators(p))
                {
                    if (await policyEvaluator.EvaluateContextAsync())
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
        #endregion

        #region HasAllPolicy
        protected virtual bool HasAllPolicy(params IPolicyContext[] policy)
        {
            var hasAll = true;

            if (policy == null || policy.Length == 0)
            {
                return false;
            }

            foreach (var p in policy)
            {
                foreach (var policyEvaluator in PolicyEvaluatorFactory.GetPolicyEvaluators(p))
                {
                    hasAll &= policyEvaluator.EvaluateContext();

                    // if validation failed already, no need to continue
                    if (!hasAll)
                    {
                        break;
                    }
                }

                if (!hasAll)
                {
                    break;
                }
            }

            return hasAll;
        }

        protected virtual async Task<bool> HasAllPolicyAsync(params IPolicyContext[] policy)
        {
            var hasAll = true;

            if (policy == null || policy.Length == 0)
            {
                return false;
            }

            foreach (var p in policy)
            {
                foreach (var policyEvaluator in PolicyEvaluatorFactory.GetPolicyEvaluators(p))
                {
                    hasAll &= await policyEvaluator.EvaluateContextAsync();

                    // if validation failed already, no need to continue
                    if (!hasAll)
                    {
                        break;
                    }
                }

                if (!hasAll)
                {
                    break;
                }
            }

            return hasAll;
        } 
        #endregion

        #region HasAllPermission
        protected virtual bool HasAllPermission(params IAuthorizationContext[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return false;
            }

            var hasAll = true;

            foreach (var perm in permissions)
            {
                foreach (var permissionEvaluator in PermissionEvaluatorFactory.GetPermissionEvaluators(perm))
                {
                    if (!permissionEvaluator.EvaluateContext())
                    {
                        hasAll = false;
                        break;
                    }
                }

                if (!hasAll)
                {
                    break;
                }
            }

            return hasAll;
        }

        protected virtual async Task<bool> HasAllPermissionAsync(params IAuthorizationContext[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return false;
            }

            var hasAll = true;

            foreach (var perm in permissions)
            {
                foreach (var permissionEvaluator in PermissionEvaluatorFactory.GetPermissionEvaluators(perm))
                {
                    if (!await permissionEvaluator.EvaluateContextAsync())
                    {
                        hasAll = false;
                        break;
                    }
                }

                if (!hasAll)
                {
                    break;
                }
            }

            return hasAll;
        }
        #endregion

        #region HasAnyPermission
        protected virtual bool HasAnyPermission(params IAuthorizationContext[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            foreach (var perm in permissions)
            {
                foreach (var permissionEvaluator in PermissionEvaluatorFactory.GetPermissionEvaluators(perm))
                {
                    if (permissionEvaluator.EvaluateContext())
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

        protected virtual async Task<bool> HasAnyPermissionAsync(params IAuthorizationContext[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            foreach (var perm in permissions)
            {
                foreach (var permissionEvaluator in PermissionEvaluatorFactory.GetPermissionEvaluators(perm))
                {
                    if (await permissionEvaluator.EvaluateContextAsync())
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
