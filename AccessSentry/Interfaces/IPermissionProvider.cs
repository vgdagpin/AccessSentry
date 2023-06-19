using System.Threading;
using System.Threading.Tasks;

namespace AccessSentry.Interfaces
{
    public interface IPermissionProvider
    {
        IAuthorizationContext AuthorizationContext { get; set; }

        bool CanUseProvider(IAuthorizationContext authorizationContext);

        bool EvaluateContext();

        Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default);
    }
}
