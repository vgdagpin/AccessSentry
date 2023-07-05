using AccessSentry.Interfaces;

using Casbin;
using Casbin.Adapter.File;
using Casbin.Model;
using Casbin.Persist;

using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AccessSentry.PermissionProviders.Casbin
{
    public class CasbinPermissionProvider : BaseCasbinPermissionProvider
    {
        #region Properties
        public override CasbinModel Model => new CasbinModel
        {
            RequestDefinition = "r = role, perm",
            PolicyDefinition = "p = role, perm",
            PolicyEffect = "e = some(where (p.eft == allow))",
            Matchers = "m = r.role == p.role && keyMatch(r.perm, p.perm)"
        };

        public override string Policy =>
    @"
p, Admin, Booking:CanRead  
p, Admin, Booking:CanWrite
p, Admin, Organization:CanCreate
"; 
        #endregion

        public override bool CanUseProvider(IAuthorizationContext authorizationContext) 
            => authorizationContext is CasbinPermissionAuthorizationContext;

        //protected string[] GetRoles()
        //{
        //    if (AuthorizationContext.User != null && AuthorizationContext.User is ClaimsPrincipal claimsPrincipal)
        //    {
        //        return claimsPrincipal.FindAll(ClaimTypes.Role).Select(a => a.Value).ToArray();
        //    }

        //    return Array.Empty<string>();
        //}

        public override bool EvaluateContext()
        {
            var authContext = AuthorizationContext as CasbinPermissionAuthorizationContext;

            if (authContext == null || authContext.Permissions == null || authContext.Permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            var enforcer = GetEnforcer();
            //var roles = GetRoles();

            foreach (var permission in authContext.Permissions)
            {
                if (!string.IsNullOrWhiteSpace(authContext.User)
                    && enforcer.Enforce(authContext.User, permission))
                {
                    hasAny = true;
                    break;
                }

                //foreach (var role in roles)
                //{
                //    var result = enforcer.Enforce(role, permission);

                //    if (result)
                //    {
                //        hasAny = true;
                //        break;
                //    }
                //}

                //if (hasAny)
                //{
                //    break;
                //}
            }

            return hasAny;
        }

        public override async Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default)
        {
            var authContext = AuthorizationContext as CasbinPermissionAuthorizationContext;

            if (authContext == null || authContext.Permissions == null || authContext.Permissions.Length == 0)
            {
                return false;
            }

            var hasAny = false;

            var enforcer = GetEnforcer();
            //var roles = GetRoles();

            foreach (var permission in authContext.Permissions)
            {
                if (!string.IsNullOrWhiteSpace(authContext.User)
                    && enforcer.Enforce(authContext.User, permission))
                {
                    hasAny = true;
                    break;
                }
                //foreach (var role in roles)
                //{
                //    var result = await enforcer.EnforceAsync(role, permission);

                //    if (result)
                //    {
                //        hasAny = true;
                //        break;
                //    }
                //}

                //if (hasAny)
                //{
                //    break;
                //}
            }

            return hasAny;
        }


        public class CasbinPermissionAuthorizationContext : IAuthorizationContext
        {
            public virtual string[] Permissions { get; set; } = null!;
            public string User { get; }

            public CasbinPermissionAuthorizationContext(string principal, params string[] permissions)
            {
                User = principal;
                Permissions = permissions;
            }
        }
    }

}
