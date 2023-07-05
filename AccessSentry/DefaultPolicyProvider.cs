﻿using AccessSentry.Interfaces;

using System.Collections.Generic;
using System.Text;

namespace AccessSentry
{
    public class DefaultPolicyProvider : IPolicyProvider
    {
        public virtual string GetPolicy()
        {
            // https://github.com/casbin/casbin/blob/master/examples/rbac_with_deny_policy.csv
            var sb = new StringBuilder();

            foreach (var groupPerm in GetGroupPermissions())
            {
                sb.AppendLine($"p, {groupPerm.Subject}, {groupPerm.ResourceName}, {groupPerm.Action}, {(groupPerm.Allow ? "allow" : "deny")}");
            }

            foreach (var userPerm in GetUserPermissions())
            {
                sb.AppendLine($"p, {userPerm.Subject}, {userPerm.ResourceName}, {userPerm.Action}, {(userPerm.Allow ? "allow" : "deny")}");
            }

            foreach (var groupMembership in GetGroupMemberships())
            {
                sb.AppendLine($"g, {groupMembership.MemberName}, {groupMembership.GroupName}");
            }

            return sb.ToString();
        }

        protected virtual IEnumerable<RBACPolicy> GetGroupPermissions()
        {
            // p, data2_admin, data2, read, allow/deny

            return new List<RBACPolicy>();
        }

        protected virtual IEnumerable<RBACPolicy> GetUserPermissions()
        {
            // p, alice, data1, read, allow/deny
            return new List<RBACPolicy>();
        }

        protected virtual IEnumerable<RBACGroupMembership> GetGroupMemberships()
        {
            // g, alice, data2_admin
            return new List<RBACGroupMembership>();
        }
    }
}