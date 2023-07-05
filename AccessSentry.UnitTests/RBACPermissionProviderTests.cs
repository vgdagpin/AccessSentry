using AccessSentry.Interfaces;
using AccessSentry.PermissionProviders.Casbin;

using Microsoft.Extensions.DependencyInjection;

using Moq;

using System.Text;

using static AccessSentry.PermissionProviders.Casbin.RBACPermissionProvider;

namespace AccessSentry.UnitTests;

public class RBACPermissionProviderTests
{
    /// <summary>
    /// https://github.com/casbin/casbin/blob/master/examples/rbac_with_deny_policy.csv
    /// </summary>
    [Theory]
    [InlineData("001", "alice", "data1", "read", true)]

    // allowed because alice is a member of data2_admin (#6); data2_admin has read permission on data2 (#1)
    [InlineData("002", "alice", "data2", "read", true)]

    // even if alice is a member of data2_admin (#6) and it says data2_admin has write permission on data2 (#2),
    // alice is denied because she has a deny write permission on data2 (#5)
    [InlineData("003", "alice", "data2", "write", false)]
    [InlineData("004", "vince", "data1", "read", false)]
    [InlineData("005", "bob", "data2", "write", true)]
    public void TestHandler(string _, string sub, string obj, string act, bool hasPermission)
    {
        var mockPolicyProvider = new Mock<IPolicyProvider>();

        var sb = new StringBuilder();

        sb.AppendLine($"p, data2_admin, data2, read, allow"); // #1
        sb.AppendLine($"p, data2_admin, data2, write, allow"); // #2

        sb.AppendLine($"p, alice, data1, read, allow"); // #3
        sb.AppendLine($"p, bob, data2, write, allow"); // #4
        sb.AppendLine($"p, alice, data2, write, deny"); // #5

        sb.AppendLine($"g, alice, data2_admin"); // #6

        mockPolicyProvider.Setup(a => a.GetPolicy()).Returns(sb.ToString());

        var permissionProvider = new RBACPermissionProvider(mockPolicyProvider.Object);

        permissionProvider.AuthorizationContext = new RBACAuthorizationContext(sub, Permission.Other(obj, act));

        var result = permissionProvider.EvaluateContext();

        Assert.Equal(hasPermission, result);
    }
}
