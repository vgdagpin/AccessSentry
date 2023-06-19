using AccessSentry.EFCorePolicyProvider.Entities;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

using System.Text;

namespace AccessSentry.EFCorePolicyProvider;

public class EFPolicyProvider : IPolicyProvider
{
    private readonly AccessSentryDbContext accessSentryDbContext;
    private readonly IMemoryCache memoryCache;

    public EFPolicyProvider(AccessSentryDbContext accessSentryDbContext, IMemoryCache memoryCache)
    {
        this.accessSentryDbContext = accessSentryDbContext;
        this.memoryCache = memoryCache;
    }

    public string GetPolicy()
    {
        var cacheKey = $"{nameof(EFPolicyProvider)}:{nameof(GetPolicy)}";

        var policy = memoryCache.Get<string>(cacheKey);

        if (policy == null)
        {
            var sb = new StringBuilder();

            foreach (var role in GetRolePermissions())
            {
                foreach (var perm in role.Permissions)
                {
                    sb.AppendLine($"p, {role.Name}, {perm.Name}, {perm.Action}");
                }
            }

            policy = sb.ToString();

            memoryCache.Set(cacheKey, policy);
        }

        return policy;
    }

    public IEnumerable<Role> GetRolePermissions()
    {
        var rrpList = accessSentryDbContext.RoleResourcePermissions
           .Include(a => a.N_Role)
           .Include(a => a.N_ResourcePermission).ThenInclude(a => a.N_Resource).ThenInclude(a => a.N_ParentResource)
           .ToList();

        var rolePermissions = new List<Role>();

        foreach (var rr in rrpList.GroupBy(a => a.N_Role))
        {
            var rolePermission = new Role
            {
                RoleID = rr.Key.RoleID,
                Name = rr.Key.Name,
                Description = rr.Key.Description,
                Permissions = rr.Select(a => new ResourcePermission
                {
                    ResourceID = a.N_ResourcePermission.ResourceID,
                    Description = a.N_ResourcePermission.Description,
                    ResourcePermissionID = a.N_ResourcePermission.ResourcePermissionID,
                    Action = a.N_ResourcePermission.Action,
                    Name = string.Join("/", TryGetResourceName(a.N_ResourcePermission.N_Resource).Reverse())
                })
            };

            rolePermissions.Add(rolePermission);
        }

        return rolePermissions;
    }

    protected virtual string[] TryGetResourceName(tbl_Resource resource)
    {
        if (resource.N_ParentResource == null)
        {
            return new[] { resource.Name };
        }

        var list = new List<string>
        {
            resource.Name
        };

        list.AddRange(TryGetResourceName(resource.N_ParentResource));

        return list.ToArray();
    }
}
