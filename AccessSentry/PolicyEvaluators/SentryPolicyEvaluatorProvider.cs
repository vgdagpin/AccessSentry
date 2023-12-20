using AccessSentry.AuthorizationAttributes;
using AccessSentry.Interfaces;
using AccessSentry.PermissionProviders.Casbin;

using Casbin;
using Casbin.Model;
using Casbin.Persist;
using Casbin.Persist.Adapter.File;

using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AccessSentry.PolicyEvaluators
{
    public class SentryPolicyEvaluatorProvider : IPolicyEvaluator
    {
        private IModel? model;

        protected IPolicyContext? PolicyContext;
        private readonly IPolicyProvider p_PolicyProvider;

        public CasbinModel Model => new CasbinModel
        {
            RequestDefinition = "r = sub, obj, act",
            PolicyDefinition = new[] { "p = sub, obj, act, eft" },
            RoleDefinition = new[] { "g = _, _" },
            PolicyEffect = "e = some(where (p.eft == allow)) && !some(where (p.eft == deny))",
            Matchers = new[] { $"m = g(p.sub, r.sub) && r.obj == p.obj && r.act == p.act" }
        };

        public SentryPolicyEvaluatorProvider(IPolicyProvider policyProvider)
        {
            p_PolicyProvider = policyProvider;
        }

        public bool CanUseProvider(IPolicyContext policyContext)
        {
            if (policyContext is SentryPolicyAttribute policyCtx)
            {
                PolicyContext = policyCtx;

                return true;
            }

            return false;
        }

        public bool EvaluateContext()
        {
            if (PolicyContext == null
                || PolicyContext.User == null
                || string.IsNullOrWhiteSpace(PolicyContext.Policy))
            {
                return false;
            }

            var subject = GetSubject(PolicyContext.User);
            var enforcer = GetEnforcer(subject);

            return enforcer.GetImplicitRolesForUser(subject).Contains(PolicyContext.Policy);
        }

        public Task<bool> EvaluateContextAsync(CancellationToken cancellationToken = default)
        {
            if (PolicyContext == null
                || PolicyContext.User == null
                || string.IsNullOrWhiteSpace(PolicyContext.Policy))
            {
                return Task.FromResult(false);
            }

            var subject = GetSubject(PolicyContext.User);
            var enforcer = GetEnforcer(subject);

            return Task.FromResult(enforcer.GetImplicitRolesForUser(subject).Contains(PolicyContext.Policy));
        }

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
                    if (!string.IsNullOrEmpty(nameClaim.Value))
                    {
                        return nameClaim.Value;
                    }
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

        public string GetPolicy(string? subject = null)
        {
            return p_PolicyProvider.GetPolicy(subject);
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
}
