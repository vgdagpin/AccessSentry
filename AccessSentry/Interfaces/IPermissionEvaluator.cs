using System.Collections;
using System.Collections.Generic;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace AccessSentry.Interfaces
{
    public interface IPermissionEvaluator
    {
        IAuthorizationContext AuthorizationContext { get; set; }

        bool CanUseEvaluator(IAuthorizationContext authorizationContext);

        bool EvaluateContext();

        Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default);


        IEnumerable<RBACPolicy> GetUserPermissions();
    }
}