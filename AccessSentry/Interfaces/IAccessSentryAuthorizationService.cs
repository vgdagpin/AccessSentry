using System.Collections.Generic;
using System.Security.Principal;
using System.Threading.Tasks;

namespace AccessSentry.Interfaces
{
    public interface IAccessSentryAuthorizationService
    {
        bool EvaluatePermission(IPrincipal principal, Enums.Has has, params string[] permissions);
        Task<bool> EvaluatePermissionAsync(IPrincipal principal, Enums.Has has, params string[] permissions);

        bool EvaluatePermission(IPrincipal principal, Enums.Has has, params Permission[] permissions);
        Task<bool> EvaluatePermissionAsync(IPrincipal principal, Enums.Has has, params Permission[] permissions);
        

        bool EvaluatePolicy(IPrincipal principal, Enums.Has has, params string[] policy);
        Task<bool> EvaluatePolicyAsync(IPrincipal principal, Enums.Has has, params string[] policy);


        IEnumerable<UserPermission> GetUserPermissions(IPrincipal principal);
        string[] GetUserMemberships(IPrincipal principal);
    }
}
