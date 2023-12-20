using AccessSentry.Interfaces;

using System;
using System.Security.Principal;

namespace AccessSentry.AuthorizationAttributes
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class SentryPolicyAttribute : Attribute, IPolicyContext
    {
        public SentryPolicyAttribute(string policy)
        {
            Policy = policy;
        }

        public string Policy { get; set; }
        public IPrincipal User { get; set; } = null!;
    }
}