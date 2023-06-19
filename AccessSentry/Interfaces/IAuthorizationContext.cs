using System.Security.Principal;

namespace AccessSentry.Interfaces
{
    public interface IAuthorizationContext
    {
        IPrincipal User { get; }
    }
}
