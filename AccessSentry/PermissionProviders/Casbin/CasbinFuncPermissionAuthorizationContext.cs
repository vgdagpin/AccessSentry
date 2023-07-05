using AccessSentry.Interfaces;

using System;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace AccessSentry.PermissionProviders.Casbin
{
    public class CasbinFuncPermissionProvider : BaseCasbinPermissionProvider
    {
        #region Properties
        public override CasbinModel Model { get; }
        public override string Policy { get; } 
        #endregion

        public override bool CanUseProvider(IAuthorizationContext authorizationContext) 
            => authorizationContext is CasbinFuncPermissionAuthorizationContext;

        public override bool EvaluateContext()
        {
            throw new NotImplementedException();
        }

        public override Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public class CasbinFuncPermissionAuthorizationContext : IAuthorizationContext
        {
            public virtual Func<string, bool> Expression { get; set; }
            public string User { get; }

            public CasbinFuncPermissionAuthorizationContext(string principal, Func<string, bool> permissionExpression)
            {
                User = principal;
                Expression = permissionExpression;
            }
        }
    }
}