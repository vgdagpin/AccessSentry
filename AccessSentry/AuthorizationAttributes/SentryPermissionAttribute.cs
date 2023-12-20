using System;

namespace AccessSentry.AuthorizationAttributes
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class SentryPermissionAttribute : Attribute
    {
        public SentryPermissionAttribute(string resource, string action)
        {
            Resource = resource;
            Action = action;
        }

        public string Resource { get; }
        public string Action { get; }
    }
}