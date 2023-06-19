using AccessSentry.Interfaces;

using Microsoft.Extensions.DependencyInjection;

using System;
using System.Collections.Generic;

namespace AccessSentry
{
    public class PolicyEvaluatorFactory : IPolicyEvaluatorFactory
    {
        private readonly IServiceProvider serviceProvider;

        public PolicyEvaluatorFactory(IServiceProvider serviceProvider)
        {
            this.serviceProvider = serviceProvider;
        }

        public IEnumerable<IAttributePolicyEvaluator> GetPolicyEvaluators(IAttributePolicy attributePolicy)
        {
            foreach (var sp in serviceProvider.GetServices<IAttributePolicyEvaluator>())
            {
                if (sp.IsAttributeEvaluator(attributePolicy))
                {
                    yield return sp;
                }
            }
        }
    }
}
