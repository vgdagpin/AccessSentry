using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace AccessSentry.Interfaces
{
    public interface IAccessSentryAuthorizationService
    {
        public IPermissionProviderFactory PermissionProviderFactory { get; }


        bool HasAnyPermission(params string[] permissions);
        Task<bool> HasAnyPermissionAsync(params string[] permissions);

        bool HasAnyPermission(params Permission[] permissions);
        Task<bool> HasAnyPermissionAsync(params Permission[] permissions);

        bool HasAllPermission(params string[] permissions);
        Task<bool> HasAllPermissionAsync(params string[] permissions);

        bool HasAllPermission(params Permission[] permissions);
        Task<bool> HasAllPermissionAsync(params Permission[] permissions);

        bool EvaluatePermission(Func<string, bool> permissionExpression);
        Task<bool> EvaluatePermissionAsync(Func<string, bool> permissionExpression);

        bool EvaluatePermission(Func<Permission, bool> permissionExpression);
        Task<bool> EvaluatePermissionAsync(Func<Permission, bool> permissionExpression);
    }
}
