using System.Collections.Generic;
using System.Security.Principal;
using System.Threading.Tasks;

namespace AccessSentry.Interfaces
{
    public interface IAccessSentryAuthorizationService
    {
        bool EvaluatePermission(Enums.Has has, params IAuthorizationContext[] permissions);
        Task<bool> EvaluatePermissionAsync(Enums.Has has, params IAuthorizationContext[] permissions);
        

        bool EvaluatePolicy(Enums.Has has, params IPolicyContext[] policy);
        Task<bool> EvaluatePolicyAsync(Enums.Has has, params IPolicyContext[] policy);


        IEnumerable<RBACPolicy> GetUserPermissions(IPrincipal principal);
        string[] GetUserMemberships(IPrincipal principal);
    }
}
