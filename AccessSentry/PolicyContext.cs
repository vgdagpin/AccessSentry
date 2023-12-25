using AccessSentry.Interfaces;

using System.Security.Principal;

namespace AccessSentry
{
    public class PolicyContext : IPolicyContext
    {
        public IPrincipal User { get; set; } = null!;
        public string Policy { get; set; } = null!;

        public PolicyContext(IPrincipal user)
        {
            User = user;
        }
    }
}
