using System.ComponentModel.DataAnnotations;

namespace AccessSentry.EFCorePolicyProvider.Entities;

public partial class tbl_ResourcePermission
{
    [Key]
    public short ResourcePermissionID { get; set; }

    [Required]
    [MaxLength(50)]
    public string Action { get; set; }

    public short ResourceID { get; set; }

    public string Description { get; set; }

    public tbl_Resource N_Resource { get; set; }
}