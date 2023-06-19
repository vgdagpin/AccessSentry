using AspNetCoreWebAPI.AuthorizationAttributes;
using AspNetCoreWebAPI.Models;

using Microsoft.AspNetCore.Mvc;

namespace AspNetCoreWebAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class SampleABACController : ControllerBase
{
    [HttpPost]
    [Route("CreateTestData")]
    [ManagerOfTestModel(parameterName: nameof(testModel))]
    public IActionResult CreateTestData(TestModel testModel)
    {
        return new JsonResult(testModel);
    }
}