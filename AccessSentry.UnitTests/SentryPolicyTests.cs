using AccessSentry.AuthorizationAttributes;
using AccessSentry.Interfaces;
using AccessSentry.PolicyEvaluators;

using Casbin;
using Casbin.Model;
using Casbin.Persist.Adapter.File;

using Moq;

using System.Security.Claims;
using System.Text;

namespace AccessSentry.UnitTests;

public class SentryPolicyTests
{
    [Theory]
    [InlineData("u::teng", "r::group_2", true)]
    public void TestEvaluator(string user, string policy, bool expectedResult)
    {
        var mockPolicyProvider = new Mock<IPolicyProvider>();

        var sb = new StringBuilder();

        sb.AppendLine($"p, r::group_3, data, read, allow");

        sb.AppendLine($"g, r::group_4, u::doe");
        sb.AppendLine($"g, r::group_2, r::group_3"); // group_2 is a member of group_3
        sb.AppendLine($"g, u::vince, r::group_3"); // vince is a member of group_3
        sb.AppendLine($"g, u::teng, r::group_2"); // teng is a member of group_2

        mockPolicyProvider.Setup(a => a.GetPolicy(It.IsAny<string>())).Returns(sb.ToString());

        var mockPolicyEval = new Mock<SentryPolicyEvaluatorProvider>(mockPolicyProvider.Object) { CallBase = true };
        
        var policyEval = mockPolicyEval.Object;

        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, user) }));

        var sentryPolicyAttr = new SentryPolicyAttribute(policy)
        {
            User = principal
        };

        if (!policyEval.CanUseProvider(sentryPolicyAttr))
        {
            throw new InvalidOperationException("Invalid policy type");
        }

        var result = policyEval.EvaluateContext();

        Assert.Equal(expectedResult, result);
    }

    private string Model
    {
        get
        {
            return
@"
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
";
        }
    }

    [Theory]
    [InlineData("u::u1", "g::g2", "g::g1", "g::g0")] // u1 is a member of g2 (#6); g2 is a member of g1 (#5); g1 is a member of g0 (#4)
    [InlineData("u::u3", "g::g9", "g::g0")]
    public void TestMembership(string user, params string[] expectedRoles)
    {
        var model = DefaultModel.CreateFromText(Model);

        var sb = new StringBuilder();

        sb.AppendLine($"p, g::g0, data_x, read, allow");

        sb.AppendLine($"g, g::g9, g::g0"); // g9 is a member of g0 :#1
        sb.AppendLine($"g, g::g8, g::g9"); // g8 is a member of g9 :#2
        sb.AppendLine($"g, u::u3, g::g9"); // u3 is a member of g9 :#3

        sb.AppendLine($"g, g::g1, g::g0"); // g1 is a member of g0 :#4
        sb.AppendLine($"g, g::g2, g::g1"); // g2 is a member of g1 :#5
        sb.AppendLine($"g, u::u1, g::g2"); // u1 is a member of g2 :#6
        sb.AppendLine($"g, u::u2, g::g2"); // u2 is a member of g2 :#7

        var policy = new FileAdapter(new MemoryStream(Encoding.UTF8.GetBytes(sb.ToString())));

        var enforcer = new Enforcer(model, policy);

        var userRoles = enforcer.GetImplicitRolesForUser(user);

        var r = enforcer.Enforce(user, "data_x", "read");

        Assert.True(r);
        Assert.Equal(expectedRoles, userRoles.ToArray());
    }
}
