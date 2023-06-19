using AccessSentry.Interfaces;

using System;

namespace AccessSentry.AuthorizationAttributes
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class AuthorizePolicyAttribute : Attribute, IAttributePolicy
    {
        public AuthorizePolicyAttribute(string parameterName)
        {
            ParameterName = parameterName;
        }

        public string ParameterName { get; }
    }
}