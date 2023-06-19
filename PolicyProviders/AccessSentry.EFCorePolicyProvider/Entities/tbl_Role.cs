using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccessSentry.EFCorePolicyProvider.Entities;

public partial class tbl_Role
{
    [Key]
    public short RoleID { get; set; }

    [Required]
    [MaxLength(100)]
    public string Name { get; set; }

    [MaxLength(300)]
    public string Description { get; set; }
}
