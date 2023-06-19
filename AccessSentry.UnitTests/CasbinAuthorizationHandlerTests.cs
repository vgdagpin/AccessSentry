using AccessSentry.PermissionProviders.Casbin;
using static AccessSentry.PermissionProviders.Casbin.CasbinPermissionProvider;
using System.Security.Claims;
using System.Text;
using Moq;

namespace AccessSentry.UnitTests;

public class CasbinAuthorizationHandlerTests
{
    [Theory]
    [InlineData("Admin", "Booking:CanRead", true)]
    [InlineData("NotAdmin", "Booking:CanRead", false)]
    public void TestHandler(string role, string permission, bool hasSucceeded)
    {
        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(ClaimTypes.Role, role));

        var authContext = new Mock<CasbinPermissionAuthorizationContext>(new ClaimsPrincipal(identity));
        authContext.Setup(a => a.Permissions).Returns(new[] { permission });


        var policy = new StringBuilder();

        policy.AppendLine("p, Admin, Booking:CanRead");
        policy.AppendLine("p, Admin, Booking:CanWrite");

        var casbinPermissionProvider = new Mock<CasbinPermissionProvider>() { CallBase = true };

        casbinPermissionProvider.Setup(a => a.Policy).Returns(policy.ToString());

        casbinPermissionProvider.Setup(a => a.AuthorizationContext)
            .Returns(authContext.Object);

        var result = casbinPermissionProvider.Object.EvaluateContext();

        Assert.Equal(hasSucceeded, result);
    }
}