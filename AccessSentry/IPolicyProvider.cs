using System;
using System.Collections.Generic;
using System.Text;

namespace AccessSentry
{
    public interface IPolicyProvider
    {
        IEnumerable<Role> GetRolePermissions();

        string GetPolicy();
    }
}
