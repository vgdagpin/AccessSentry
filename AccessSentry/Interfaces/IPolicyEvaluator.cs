using System.Threading;
using System.Threading.Tasks;

namespace AccessSentry.Interfaces
{
    public interface IPolicyEvaluator
    {
        bool CanUseProvider(IPolicyContext policyContext);

        bool EvaluateContext();

        Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default);
    }
}
