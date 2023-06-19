using System;
using System.Collections.Generic;
using System.Text;

namespace AccessSentry.Interfaces
{
    public interface IPolicyEvaluatorFactory
    {
        IEnumerable<IAttributePolicyEvaluator> GetPolicyEvaluators(IAttributePolicy attributePolicy);
    }
}
