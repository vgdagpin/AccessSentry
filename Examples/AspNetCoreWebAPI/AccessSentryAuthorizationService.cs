using AccessSentry;
using AccessSentry.Interfaces;

using System.Security.Principal;

using static AccessSentry.PermissionProviders.Casbin.CasbinFuncPermissionProvider;
using static AccessSentry.PermissionProviders.Casbin.RBACPermissionProvider;

namespace AspNetCoreWebAPI;

public class AccessSentryAuthorizationService : IAccessSentryAuthorizationService
{
    private readonly IPrincipal principal;

    public IPermissionProviderFactory PermissionProviderFactory { get; }

    public AccessSentryAuthorizationService(IPermissionProviderFactory permissionProviderFactory, IPrincipal principal)
    {
        PermissionProviderFactory = permissionProviderFactory;
        this.principal = principal;
    }


    #region HasAllPermission
    public bool HasAllPermission(params string[] permissions)
    {
        if (permissions == null || permissions.Length == 0)
        {
            return false;
        }

        var hasAll = true;

        var authContext = new RBACAuthorizationContext(principal, permissions.Select(Permission.Parse).ToArray());

        foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
        {
            if (!permissionProvider.EvaluateContext())
            {
                hasAll = false;
                break;
            }
        }

        return hasAll;
    }

    public async Task<bool> HasAllPermissionAsync(params string[] permissions)
    {
        if (permissions == null || permissions.Length == 0)
        {
            return false;
        }

        var hasAll = true;

        var authContext = new RBACAuthorizationContext(principal, permissions.Select(Permission.Parse).ToArray());

        foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
        {
            if (!await permissionProvider.EvaluateContextAsync())
            {
                hasAll = false;
                break;
            }
        }

        return hasAll;
    }

    public bool HasAllPermission(params Permission[] permissions)
    {
        if (permissions == null || permissions.Length == 0)
        {
            return false;
        }

        var hasAll = true;

        var authContext = new RBACAuthorizationContext(principal, permissions);

        foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
        {
            if (!permissionProvider.EvaluateContext())
            {
                hasAll = false;
                break;
            }
        }

        return hasAll;
    }

    public async Task<bool> HasAllPermissionAsync(params Permission[] permissions)
    {
        if (permissions == null || permissions.Length == 0)
        {
            return false;
        }

        var hasAll = true;

        var authContext = new RBACAuthorizationContext(principal, permissions);

        foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
        {
            if (!await permissionProvider.EvaluateContextAsync())
            {
                hasAll = false;
                break;
            }
        }

        return hasAll;
    } 
    #endregion

    #region HasAnyPermission
    public bool HasAnyPermission(params string[] permissions)
    {
        if (permissions == null || permissions.Length == 0)
        {
            return false;
        }

        var hasAny = false;

        var authContext = new RBACAuthorizationContext(principal, permissions.Select(Permission.Parse).ToArray());

        foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
        {
            if (permissionProvider.EvaluateContext())
            {
                hasAny = true;
                break;
            }
        }

        return hasAny;
    }

    public async Task<bool> HasAnyPermissionAsync(params string[] permissions)
    {
        if (permissions == null || permissions.Length == 0)
        {
            return false;
        }

        var hasAny = false;

        var authContext = new RBACAuthorizationContext(principal, permissions.Select(Permission.Parse).ToArray());

        foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
        {
            if (await permissionProvider.EvaluateContextAsync())
            {
                hasAny = true;
                break;
            }
        }

        return hasAny;
    }

    public bool HasAnyPermission(params Permission[] permissions)
    {
        if (permissions == null || permissions.Length == 0)
        {
            return false;
        }

        var hasAny = false;

        var authContext = new RBACAuthorizationContext(principal, permissions);

        foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
        {
            if (permissionProvider.EvaluateContext())
            {
                hasAny = true;
                break;
            }
        }

        return hasAny;
    }

    public async Task<bool> HasAnyPermissionAsync(params Permission[] permissions)
    {
        if (permissions == null || permissions.Length == 0)
        {
            return false;
        }

        var hasAny = false;

        var authContext = new RBACAuthorizationContext(principal, permissions);

        foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
        {
            if (await permissionProvider.EvaluateContextAsync())
            {
                hasAny = true;
                break;
            }
        }

        return hasAny;
    }
    #endregion

    #region EvaluatePermission
    public bool EvaluatePermission(Func<string, bool> permissionExpression)
    {
        if (permissionExpression == null)
        {
            return false;
        }

        var hasAll = true;

        var authContext = new CasbinFuncPermissionAuthorizationContext(principal, permissionExpression);

        foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
        {
            if (!permissionProvider.EvaluateContext())
            {
                hasAll = false;
                break;
            }
        }

        return hasAll;
    }

    public async Task<bool> EvaluatePermissionAsync(Func<string, bool> permissionExpression)
    {
        if (permissionExpression == null)
        {
            return false;
        }

        var hasAll = true;

        var authContext = new CasbinFuncPermissionAuthorizationContext(principal, permissionExpression);

        foreach (var permissionProvider in PermissionProviderFactory.GetPermissionProviders(authContext))
        {
            if (!await permissionProvider.EvaluateContextAsync())
            {
                hasAll = false;
                break;
            }
        }

        return hasAll;
    }

    public bool EvaluatePermission(Func<Permission, bool> permissionExpression)
    {
        throw new NotImplementedException();
    }

    public Task<bool> EvaluatePermissionAsync(Func<Permission, bool> permissionExpression)
    {
        throw new NotImplementedException();
    } 
    #endregion
}