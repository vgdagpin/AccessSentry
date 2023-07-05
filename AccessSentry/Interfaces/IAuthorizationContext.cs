using System.Security.Principal;

namespace AccessSentry.Interfaces
{
    public interface IAuthorizationContext
    {
        string User { get; }
    }
}
