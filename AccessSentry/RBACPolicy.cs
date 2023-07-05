using System;
using System.Collections.Generic;
using System.Text;

namespace AccessSentry
{
    public class RBACPolicy
    {
        public string Subject { get; set; }
        public string ResourceName { get; set; }
        public string Action { get; set; }
        public bool Allow { get; set; }
    }
}
