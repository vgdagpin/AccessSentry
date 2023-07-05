using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace AccessSentry.Interfaces
{
    public interface IAccessSentryAuthorizationService
    {
        public IPermissionProviderFactory PermissionProviderFactory { get; }


        bool HasAnyPermission(IPrincipal principal, params string[] permissions);
        Task<bool> HasAnyPermissionAsync(IPrincipal principal, params string[] permissions);

        bool HasAnyPermission(IPrincipal principal, params Permission[] permissions);
        Task<bool> HasAnyPermissionAsync(IPrincipal principal, params Permission[] permissions);

        bool HasAllPermission(IPrincipal principal, params string[] permissions);
        Task<bool> HasAllPermissionAsync(IPrincipal principal, params string[] permissions);

        bool HasAllPermission(IPrincipal principal, params Permission[] permissions);
        Task<bool> HasAllPermissionAsync(IPrincipal principal, params Permission[] permissions);

        bool EvaluatePermission(IPrincipal principal, Func<string, bool> permissionExpression);
        Task<bool> EvaluatePermissionAsync(IPrincipal principal, Func<string, bool> permissionExpression);

        bool EvaluatePermission(IPrincipal principal, Func<Permission, bool> permissionExpression);
        Task<bool> EvaluatePermissionAsync(IPrincipal principal, Func<Permission, bool> permissionExpression);
    }
}
