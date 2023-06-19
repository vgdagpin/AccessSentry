using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccessSentry.EFCorePolicyProvider.Entities;

public partial class tbl_RoleResourcePermission
{
    public short RoleID { get; set; }
    public short ResourcePermissionID { get; set; }

    public tbl_Role N_Role { get; set; }
    public tbl_ResourcePermission N_ResourcePermission { get; set; }
}