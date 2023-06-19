using System.ComponentModel.DataAnnotations;

namespace AccessSentry.EFCorePolicyProvider.Entities;

public partial class tbl_Resource
{
    [Key]
    public short ResourceID { get; set; }

    [Required]
    [MaxLength(100)]
    public string Name { get; set; }

    [Required]
    [MaxLength(300)]
    public string Description { get; set; }

    public short? ParentResourceID { get; set; }

    public tbl_Resource N_ParentResource { get; set; }
}