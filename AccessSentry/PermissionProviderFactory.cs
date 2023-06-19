using AccessSentry.Interfaces;

using Microsoft.Extensions.DependencyInjection;

using System;
using System.Collections.Generic;

namespace AccessSentry
{
    public class PermissionProviderFactory : IPermissionProviderFactory
    {
        private readonly IServiceProvider serviceProvider;

        public PermissionProviderFactory(IServiceProvider serviceProvider)
        {
            this.serviceProvider = serviceProvider;
        }

        public IEnumerable<IPermissionProvider> GetPermissionProviders(IAuthorizationContext authorizationContext)
        {
            foreach (var sp in serviceProvider.GetServices<IPermissionProvider>())
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
