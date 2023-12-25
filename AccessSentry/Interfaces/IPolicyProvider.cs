using Casbin;

namespace AccessSentry.Interfaces
{
    public interface IPolicyProvider
    {
        string GetPolicy(string? subject = null);
        IEnforcer GetEnforcer(string? subject = null);
    }
}