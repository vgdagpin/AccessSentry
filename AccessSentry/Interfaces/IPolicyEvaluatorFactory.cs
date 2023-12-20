using System.Collections.Generic;

namespace AccessSentry.Interfaces
{
    public interface IPolicyEvaluatorFactory
    {
        IEnumerable<IPolicyEvaluator> GetPolicyEvaluators(IPolicyContext policyContext);
    }
}
