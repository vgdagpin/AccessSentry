using AccessSentry.Interfaces;

using Casbin.Model;
using Casbin;

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Casbin.Adapter.File;
using Casbin.Persist;
using System.IO;

namespace AccessSentry.PermissionProviders.Casbin
{
    public abstract class BaseCasbinPermissionProvider : IPermissionProvider
    {
        private IModel? model;

        public virtual IAuthorizationContext AuthorizationContext { get; set; }

        /// <summary>
        /// Get the model to use for casbin (eg. RBAC,ABAC, etc..)
        /// <br /><br />
        /// See https://casbin.org/docs/supported-models for more supported models
        /// </summary>
        public abstract CasbinModel Model { get; }

        public abstract bool CanUseProvider(IAuthorizationContext authorizationContext);

        public abstract bool EvaluateContext();

        public abstract string GetPolicy(string? subject = null);

        public abstract Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default);


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
        protected virtual IReadOnlyAdapter GetFileAdapter(string subject)
        {
            var policy = GetPolicy(subject);

            if (string.IsNullOrWhiteSpace(policy))
            {
                throw new ArgumentNullException(nameof(policy));
            }

            return new FileAdapter(new MemoryStream(Encoding.UTF8.GetBytes(policy)));
        }

        protected virtual IEnforcer GetEnforcer(string subject)
        {
            var model = GetModel();
            var adapter = GetFileAdapter(subject);

            return new Enforcer(model, adapter);
        }
    }

    public class CasbinModel
    {
        public string RequestDefinition { get; set; } = null!;
        public string[] PolicyDefinition { get; set; } = null!;
        public string[]? RoleDefinition { get; set; }
        public string PolicyEffect { get; set; } = null!;
        public string[] Matchers { get; set; } = null!;

        public override string ToString()
        {
            var sb = new StringBuilder();

            sb.AppendLine("[request_definition]");
            sb.AppendLine(RequestDefinition);
            sb.AppendLine();
            sb.AppendLine("[policy_definition]");
            foreach (var policyDef in PolicyDefinition)
            {
                sb.AppendLine(policyDef);
            }

            if (RoleDefinition != null && RoleDefinition.Length > 0)
            {
                sb.AppendLine();
                sb.AppendLine("[role_definition]");

                for (int i = 0; i < RoleDefinition.Length; i++)
                {
                    sb.AppendLine(RoleDefinition[i]);
                }
            }

            sb.AppendLine();
            sb.AppendLine("[policy_effect]");
            sb.AppendLine(PolicyEffect);
            sb.AppendLine();
            sb.AppendLine("[matchers]");
            foreach (var matcher in Matchers)
            {
                sb.AppendLine(matcher);
            }

            return sb.ToString();
        }
    }
}
