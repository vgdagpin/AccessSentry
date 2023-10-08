using AccessSentry.Interfaces;

using Casbin;
using Casbin.Model;
using Casbin.Persist;
using Casbin.Persist.Adapter.File;

using System;
using System.IO;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AccessSentry.PermissionProviders.Casbin
{
    public abstract class BaseCasbinPermissionProvider<T> : IPermissionProvider where T : IAuthorizationContext
    {
        private IModel? model;

        public virtual IAuthorizationContext AuthorizationContext { get; set; } = null!;

        /// <summary>
        /// Get the model to use for casbin (eg. RBAC,ABAC, etc..)
        /// <br /><br />
        /// See https://casbin.org/docs/supported-models for more supported models
        /// </summary>
        public abstract CasbinModel Model { get; }

        public virtual bool CanUseProvider(IAuthorizationContext authorizationContext) => authorizationContext is T;

        public abstract bool EvaluateContext();

        public abstract string GetPolicy(string? subject = null);

        public abstract Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default);

        protected virtual string GetSubject(IPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (principal is ClaimsPrincipal claimsPrincipal)
            {
                var nameClaim = claimsPrincipal.FindFirst(ClaimTypes.Name);

                if (nameClaim == null)
                {
                    nameClaim = claimsPrincipal.FindFirst(ClaimTypes.NameIdentifier);
                }

                if (nameClaim != null)
                {
                    return nameClaim.Value;
                }
            }

            throw new ArgumentNullException("No name found from principal");
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
