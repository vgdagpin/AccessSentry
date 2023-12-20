using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Text;

namespace AccessSentry.Interfaces
{
    public interface IPolicyContext
    {
        IPrincipal User { get; set; }
        string Policy { get; set; }
    }
}
