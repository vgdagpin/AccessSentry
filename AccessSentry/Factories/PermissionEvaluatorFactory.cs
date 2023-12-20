using AccessSentry.Interfaces;

using Microsoft.Extensions.DependencyInjection;

using System;
using System.Collections.Generic;

namespace AccessSentry.Factories
{
    public class PermissionEvaluatorFactory : IPermissionEvaluatorFactory
    {
        private readonly IServiceProvider serviceProvider;

        public PermissionEvaluatorFactory(IServiceProvider serviceProvider)
        {
            this.serviceProvider = serviceProvider;
        }

        public IEnumerable<IPermissionEvaluator> GetPermissionProviders(IAuthorizationContext authorizationContext)
        {
            foreach (var sp in serviceProvider.GetServices<IPermissionEvaluator>())
            {
                if (sp.CanUseProvider(authorizationContext))
                {
                    sp.AuthorizationContext = authorizationContext;

                    yield return sp;
                }
            }
        }
    }
}
