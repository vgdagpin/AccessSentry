using AccessSentry.Interfaces;

using System.Collections.Generic;
using System.Text;

namespace AccessSentry
{
    public class DefaultPolicyProvider : IPolicyProvider
    {
        public static string FormatGroupSubject(string groupName) => $"g::{groupName.ToUpper()}";
        public static string FormatUserSubject(string user) => $"u::{user.ToUpper()}";

        public virtual string GetPolicy(string? subject = null)
        {
            // https://github.com/casbin/casbin/blob/master/examples/rbac_with_deny_policy.csv
            var sb = new StringBuilder();

            foreach (var groupPerm in GetGroupPermissions(subject))
            {
                sb.AppendLine($"p, {groupPerm.Subject}, {groupPerm.ResourceName}, {groupPerm.Action}, {(groupPerm.Allow ? "allow" : "deny")}");
            }

            foreach (var userPerm in GetUserPermissions(subject))
            {
                sb.AppendLine($"p, {userPerm.Subject}, {userPerm.ResourceName}, {userPerm.Action}, {(userPerm.Allow ? "allow" : "deny")}");
            }

            foreach (var groupMembership in GetGroupMemberships(subject))
            {
                sb.AppendLine($"g, {groupMembership.GroupName}, {groupMembership.MemberName}");
            }

            return sb.ToString();
        }

        protected virtual IEnumerable<RBACPolicy> GetGroupPermissions(string? subject = null)
        {
            // p, data2_admin, data2, read, allow/deny

            return new List<RBACPolicy>();
        }

        protected virtual IEnumerable<RBACPolicy> GetUserPermissions(string? subject = null)
        {
            // p, alice, data1, read, allow/deny
            return new List<RBACPolicy>();
        }

        protected virtual IEnumerable<RBACGroupMembership> GetGroupMemberships(string? subject = null)
        {
            // g, alice, data2_admin
            return new List<RBACGroupMembership>();
        }
    }
}
