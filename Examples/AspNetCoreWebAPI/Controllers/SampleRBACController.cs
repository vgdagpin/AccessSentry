using AccessSentry;
using AccessSentry.AuthorizationAttributes;
using AccessSentry.Interfaces;

using Microsoft.AspNetCore.Mvc;

namespace AspNetCoreWebAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class SampleRBACController : ControllerBase
{
    private readonly IAccessSentryAuthorizationService authService;

    public SampleRBACController(IAccessSentryAuthorizationService authService)
    {
        this.authService = authService;
    }

    [HttpPost]
    [Route("TestActionViaMethod")]
    public IActionResult TestActionViaMethod()
    {
        if (!authService.HasAnyPermission(Constants.Permissions.Organization.CanCreate))
        {
            return new JsonResult(Constants.Permissions.Organization.CanCreate)
            {
                StatusCode = StatusCodes.Status401Unauthorized
            };
        }

        // do logic validation here

        if (!authService.HasAnyPermission(Constants.Permissions.Organization.CanAddContact))
        {
            return new JsonResult(Constants.Permissions.Organization.CanAddContact)
            {
                StatusCode = StatusCodes.Status401Unauthorized
            };
        }

        return new JsonResult(true)
        {
            StatusCode = StatusCodes.Status200OK
        };
    }

    [HttpGet]
    [Route("TestActionViaAttribute")]
    [AuthorizePermission(Enums.Has.Any, Constants.Permissions.Organization.CanCreate)]
    public IActionResult TestActionViaAttribute()
    {
        return new JsonResult(true)
        {
            StatusCode = StatusCodes.Status200OK
        };
    }
}