using System.Collections.Generic;

namespace AccessSentry.Interfaces
{
    public interface IPermissionProviderFactory
    {
        IEnumerable<IPermissionProvider> GetPermissionProviders(IAuthorizationContext authorizationContext);
    }
}
