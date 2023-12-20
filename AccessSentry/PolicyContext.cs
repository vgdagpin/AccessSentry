using AccessSentry.Interfaces;

using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Text;

namespace AccessSentry
{
    public class PolicyContext : IPolicyContext
    {
        public IPrincipal User { get; set; } = null!;
        public string Policy { get; set; } = null!;
    }
}
