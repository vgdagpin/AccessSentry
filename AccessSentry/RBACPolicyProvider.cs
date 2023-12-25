using AccessSentry.Interfaces;
using AccessSentry.PermissionProviders.Casbin;

using Casbin;
using Casbin.Model;
using Casbin.Persist.Adapter.File;
using Casbin.Persist;

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AccessSentry
{
    public class RBACPolicyProvider : IPolicyProvider
    {
        private IModel? model;

        /// <summary>
        /// Get the model to use for casbin (eg. RBAC,ABAC, etc..)
        /// <br /><br />
        /// See https://casbin.org/docs/supported-models for more supported models
        /// </summary>
        public virtual CasbinModel Model => new CasbinModel
        {
            RequestDefinition = "r = sub, obj, act",
            PolicyDefinition = new[] { "p = sub, obj, act, eft" },
            RoleDefinition = new[] { "g = _, _" },
            PolicyEffect = "e = some(where (p.eft == allow)) && !some(where (p.eft == deny))",
            Matchers = new[] { $"m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act" }
        };


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
                sb.AppendLine($"g, {groupMembership.MemberName}, {groupMembership.GroupName}");
            }

            return sb.ToString().Trim();
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

        public virtual IEnforcer GetEnforcer(string? subject = null)
        {
            var model = GetModel();
            var adapter = GetFileAdapter(subject);

            return new Enforcer(model, adapter);
        }

        protected virtual IModel GetModel()
        {
            if (model == null)
            {
                if (Model == null)
                {
                    throw new ArgumentNullException(nameof(Model));
                }

                model = DefaultModel.CreateFromText(Model.ToString().Trim());
            }

            return model;
        }

        /// <summary>
        /// Adapters to use when enforcing policy
        /// <br /><br />
        /// See https://casbin.org/docs/adapters for more adapter types
        /// </summary>
        protected virtual IReadOnlyAdapter GetFileAdapter(string? subject)
        {
            var policy = GetPolicy(subject);

            if (string.IsNullOrWhiteSpace(policy))
            {
                throw new ArgumentNullException(nameof(policy));
            }

            return new FileAdapter(new MemoryStream(Encoding.UTF8.GetBytes(policy)));
        }
    }
}
