using System;

namespace AccessSentry.AuthorizationAttributes
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class AuthorizePermissionAttribute : Attribute
    {
        public AuthorizePermissionAttribute(Enums.Has condition, params string[] permissions)
        {
            Condition = condition;
            Permissions = permissions;
        }

        public Enums.Has? Condition { get; }
        public string[] Permissions { get; }

    }
}