using AccessSentry.AuthorizationAttributes;

namespace AspNetCoreWebAPI.AuthorizationAttributes;

public class ManagerOfTestModelAttribute : AuthorizePolicyAttribute
{
    public ManagerOfTestModelAttribute(string parameterName) : base(parameterName)
    {
    }
}