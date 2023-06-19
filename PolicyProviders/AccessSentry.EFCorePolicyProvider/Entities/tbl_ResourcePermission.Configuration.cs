using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AccessSentry.EFCorePolicyProvider.Entities;

public partial class tbl_ResourcePermission : IEntityTypeConfiguration<tbl_ResourcePermission>
{
    public void Configure(EntityTypeBuilder<tbl_ResourcePermission> builder)
    {
        builder.HasOne(a => a.N_Resource)
            .WithMany()
            .HasForeignKey(a => a.ResourceID);

        builder.HasData(GetSeedData());
    }

    tbl_ResourcePermission[] GetSeedData()
    {
        var list = new List<tbl_ResourcePermission>
        {
            new tbl_ResourcePermission
            {
                ResourcePermissionID = 1,
                ResourceID = 1,
                Description = "Can view organizations",
                Action = "CanView"
            },

            new tbl_ResourcePermission
            {
                ResourcePermissionID = 2,
                ResourceID = 1,
                Description = "Can create organizations",
                Action = "CanCreate"
            },

            new tbl_ResourcePermission
            {
                ResourcePermissionID = 3,
                ResourceID = 1,
                Description = "Can delete organizations",
                Action = "CanDelete"
            },

            new tbl_ResourcePermission
            {
                ResourcePermissionID = 4,
                ResourceID = 1,
                Description = "Can do whatever you do to organizations",
                Action = "Whatever"
            },

            new tbl_ResourcePermission
            {
                ResourcePermissionID = 5,
                ResourceID = 2,
                Description = "Can add contact to organizations",
                Action = "CanAddContact"
            }
        };

        return list.ToArray();
    }
}
