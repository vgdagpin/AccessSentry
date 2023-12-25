using AccessSentry.Interfaces;

using Microsoft.Extensions.DependencyInjection;

using System;
using System.Collections.Generic;

namespace AccessSentry.Factories
{
    public class PolicyEvaluatorFactory : IPolicyEvaluatorFactory
    {
        private readonly IServiceProvider serviceProvider;

        public PolicyEvaluatorFactory(IServiceProvider serviceProvider)
        {
            this.serviceProvider = serviceProvider;
        }

        public IEnumerable<IPolicyEvaluator> GetPolicyEvaluators(IPolicyContext policyContext)
        {
            foreach (var sp in serviceProvider.GetServices<IPolicyEvaluator>())
            {
                if (sp.CanUseEvaluator(policyContext))
                {
                    yield return sp;
                }
            }
        }
    }
}
