using AccessSentry.AuthorizationAttributes;

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace AccessSentry.Interfaces
{
    public interface IAttributePolicyEvaluator
    {
        bool IsAttributeEvaluator(IPolicyContext attributePolicy);

        Task<bool> EvaluateAsync();
    }
}
