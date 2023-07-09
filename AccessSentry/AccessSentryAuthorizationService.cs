using AccessSentry.Interfaces;

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

using static AccessSentry.PermissionProviders.Casbin.CasbinFuncPermissionProvider;

using static AccessSentry.PermissionProviders.Casbin.RBACPermissionProvider;

namespace AccessSentry
{
    public class AccessSentryAuthorizationService : IAccessSentryAuthorizationService
    {
        public IPermissionProviderFactory PermissionProviderFactory { get; }

        public AccessSentryAuthorizationService(IPermissionProviderFactory permissionProviderFactory)
        {
            PermissionProviderFactory = permissionProviderFactory;
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


        #region HasAllPermission
        public bool HasAllPermission(IPrincipal principal, params string[] permissions)
        {
            

            var hasAll = true;

            var authContext = new RBACAuthorizationContext(principal, GetPermissions(permissions));

            foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
            {
                if (!permissionProvider.EvaluateContext())
                {
                    hasAll = false;
                    break;
                }
            }

            return hasAll;
        }

        public async Task<bool> HasAllPermissionAsync(IPrincipal principal, params string[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return false;
            }

            var hasAll = true;

            var authContext = new RBACAuthorizationContext(principal, GetPermissions(permissions));

            foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
            {
                if (!await permissionProvider.EvaluateContextAsync())
                {
                    hasAll = false;
                    break;
                }
            }

            return hasAll;
        }

        public bool HasAllPermission(IPrincipal principal, params Permission[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return false;
            }

            var hasAll = true;

            var authContext = new RBACAuthorizationContext(principal, permissions);

            foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
            {
                if (!permissionProvider.EvaluateContext())
                {
                    hasAll = false;
                    break;
                }
            }

            return hasAll;
        }

        public async Task<bool> HasAllPermissionAsync(IPrincipal principal, params Permission[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return false;
            }

            var hasAll = true;

            var authContext = new RBACAuthorizationContext(principal, permissions);

            foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
            {
                if (!await permissionProvider.EvaluateContextAsync())
                {
                    hasAll = false;
                    break;
                }
            }

            return hasAll;
        }
        #endregion

        #region HasAnyPermission
        public bool HasAnyPermission(IPrincipal principal, params string[] permissions)
        {
            var perms = GetPermissions(permissions);

            if (perms.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            var authContext = new RBACAuthorizationContext(principal, perms);

            foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
            {
                if (permissionProvider.EvaluateContext())
                {
                    hasAny = true;
                    break;
                }
            }

            return hasAny;
        }

        public async Task<bool> HasAnyPermissionAsync(IPrincipal principal, params string[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            var authContext = new RBACAuthorizationContext(principal, GetPermissions(permissions));

            foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
            {
                if (await permissionProvider.EvaluateContextAsync())
                {
                    hasAny = true;
                    break;
                }
            }

            return hasAny;
        }

        public bool HasAnyPermission(IPrincipal principal, params Permission[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            var authContext = new RBACAuthorizationContext(principal, permissions);

            foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
            {
                if (permissionProvider.EvaluateContext())
                {
                    hasAny = true;
                    break;
                }
            }

            return hasAny;
        }

        public async Task<bool> HasAnyPermissionAsync(IPrincipal principal, params Permission[] permissions)
        {
            if (permissions == null || permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            var authContext = new RBACAuthorizationContext(principal, permissions);

            foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
            {
                if (await permissionProvider.EvaluateContextAsync())
                {
                    hasAny = true;
                    break;
                }
            }

            return hasAny;
        }
        #endregion

        #region EvaluatePermission
        public bool EvaluatePermission(IPrincipal principal, Func<string, bool> permissionExpression)
        {
            if (permissionExpression == null)
            {
                return false;
            }

            var hasAll = true;

            var authContext = new CasbinFuncPermissionAuthorizationContext(principal, permissionExpression);

            foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
            {
                if (!permissionProvider.EvaluateContext())
                {
                    hasAll = false;
                    break;
                }
            }

            return hasAll;
        }

        public async Task<bool> EvaluatePermissionAsync(IPrincipal principal, Func<string, bool> permissionExpression)
        {
            if (permissionExpression == null)
            {
                return false;
            }

            var hasAll = true;

            var authContext = new CasbinFuncPermissionAuthorizationContext(principal, permissionExpression);

            foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
            {
                if (!await permissionProvider.EvaluateContextAsync())
                {
                    hasAll = false;
                    break;
                }
            }

            return hasAll;
        }

        public bool EvaluatePermission(IPrincipal principal, Func<Permission, bool> permissionExpression)
        {
            throw new NotImplementedException();
        }

        public Task<bool> EvaluatePermissionAsync(IPrincipal principal, Func<Permission, bool> permissionExpression)
        {
            throw new NotImplementedException();
        }
        #endregion
    }
}
