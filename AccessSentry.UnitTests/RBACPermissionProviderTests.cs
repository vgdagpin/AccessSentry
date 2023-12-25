using AccessSentry.Interfaces;
using AccessSentry.PermissionProviders.Casbin;

using Moq;

using System.Security.Claims;
using System.Text;

using static AccessSentry.PermissionProviders.Casbin.RBACPermissionEvaluatorProvider;

namespace AccessSentry.UnitTests;

public class RBACPermissionProviderTests
{
    /// <summary>
    /// https://github.com/casbin/casbin/blob/master/examples/rbac_with_deny_policy.csv
    /// https://editor.casbin.org/#HDQN6PAQT
    /// </summary>
    [Theory]
    // #4
    [InlineData("001", "u::alice", "data1", "read", true)]

    // allowed because alice is a member of data2_admin (#7); data2_admin has read permission on data2 (#2)
    [InlineData("002", "u::alice", "data2", "read", true)]

    // even if alice is a member of data2_admin (#7) and it says data2_admin has write permission on data2 (#3),
    // alice is denied because she has a deny write permission on data2 (#6)
    [InlineData("003", "u::alice", "data2", "write", false)]
    [InlineData("004", "u::vince", "data1", "read", false)]
    [InlineData("005", "u::bob", "data2", "write", true)]
    [InlineData("006", "r::data2_admin", "data2", "write", true)]
    [InlineData("007", "r::data2_reader", "data2", "write", false)]
    [InlineData("008", "u::vince", "data2", "write", false)]
    [InlineData("009", "u::vince", "data2", "read", true)]
    [InlineData("010", "r::SuperAdmin", "data2", "read", true)]
    public void TestHandler(string _, string sub, string obj, string act, bool hasPermission)
    {
        var mockPolicyProvider = new Mock<RBACPolicyProvider>() { CallBase = true };

        var sb = new StringBuilder();

        sb.AppendLine($"g, u::alice, r::data2_admin"); // #7 // alice is a member of data2_admin
        sb.AppendLine($"g, u::vince, r::data2_reader"); // #8 // vince is a member of data2_reader

        sb.AppendLine($"p, r::data2_reader, data2, read, allow"); // #1
        sb.AppendLine($"p, r::data2_admin, data2, read, allow"); // #2
        sb.AppendLine($"p, r::data2_admin, data2, write, allow"); // #3

        sb.AppendLine($"p, u::alice, data1, read, allow"); // #4
        sb.AppendLine($"p, u::bob, data2, write, allow"); // #5
        sb.AppendLine($"p, u::alice, data2, write, deny"); // #6
       

        mockPolicyProvider.Setup(a => a.GetPolicy(It.IsAny<string>())).Returns(sb.ToString());

        var mockPermissionProvider = new Mock<RBACPermissionEvaluatorProvider>(mockPolicyProvider.Object) { CallBase = true };

        var permissionProvider = mockPermissionProvider.Object;

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, sub) }));

        permissionProvider.AuthorizationContext = new RBACAuthorizationContext(principal, Permission.Other(obj, act));

        var result = permissionProvider.EvaluateContext();

        Assert.Equal(hasPermission, result);
    }

    [Theory]
    [InlineData("001", "u::vince", "data", "read", true)]
    [InlineData("002", "u::teng", "data", "read", true)]
    [InlineData("003", "u::doe", "data", "read", false)]
    public void TestHierarchyGroupingHandler(string _, string sub, string obj, string act, bool hasPermission)
    {
        var mockPolicyProvider = new Mock<RBACPolicyProvider>() { CallBase = true };

        var sb = new StringBuilder();

        sb.AppendLine($"g, u::doe, r::group_4");
        sb.AppendLine($"g, r::group_2, r::group_3"); // group_2 is a member of group_3
        sb.AppendLine($"g, u::vince, r::group_3");
        sb.AppendLine($"g, u::teng, r::group_2"); // so teng also has access to group_3 permissions

        sb.AppendLine($"p, r::group_3, data, read, allow");


        mockPolicyProvider.Setup(a => a.GetPolicy(It.IsAny<string>())).Returns(sb.ToString());

        var mockPermissionProvider = new Mock<RBACPermissionEvaluatorProvider>(mockPolicyProvider.Object) { CallBase = true };

        var permissionProvider = mockPermissionProvider.Object;

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, sub) }));

        permissionProvider.AuthorizationContext = new RBACAuthorizationContext(principal, Permission.Other(obj, act));

        var result = permissionProvider.EvaluateContext();

        Assert.Equal(hasPermission, result);
    }
}
