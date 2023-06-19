using AccessSentry.EFCorePolicyProvider;
using AccessSentry.EFCorePolicyProvider.Entities;

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AspNetCoreWebAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class AccessManagementController : ControllerBase
{
    private readonly AccessSentryDbContext accessSentryDbContext;

    public AccessManagementController(AccessSentryDbContext accessSentryDbContext)
    {
        this.accessSentryDbContext = accessSentryDbContext;
    }

    [HttpGet]
    [Route("GetRoles")]
    public IActionResult GetRoles()
    {
        var rrpList = accessSentryDbContext.RoleResourcePermissions
           .Include(a => a.N_Role)
           .Include(a => a.N_ResourcePermission).ThenInclude(a => a.N_Resource).ThenInclude(a => a.N_ParentResource)
           .ToList();

        var result = rrpList.GroupBy(a => a.N_Role).Select(rr => new
        {
            Name = rr.Key.Name,
            Description = rr.Key.Description,
            Permissions = rr.Select(a => new
            {
                Name = string.Join("/", TryGetResourceName(a.N_ResourcePermission.N_Resource).Reverse()) + ":" + a.N_ResourcePermission.Action,
                Description = a.N_ResourcePermission.Description
            })
        });

        return new JsonResult(result);
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
