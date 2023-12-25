using System.Collections.Generic;

namespace AccessSentry.Interfaces
{
    public interface IPermissionEvaluatorFactory
    {
        IEnumerable<IPermissionEvaluator> GetPermissionEvaluators(IAuthorizationContext authorizationContext);
    }
}
