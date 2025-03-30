using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace AccessSentry.Interfaces
{
    public interface IPolicyEvaluator
    {
        string[] GetUserMemberships();

        bool CanUseEvaluator(IPolicyContext policyContext);

        bool EvaluateContext();

        Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default);
    }
}
