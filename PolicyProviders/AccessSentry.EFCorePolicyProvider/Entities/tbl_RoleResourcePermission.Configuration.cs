using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AccessSentry.EFCorePolicyProvider.Entities;

public partial class tbl_RoleResourcePermission : IEntityTypeConfiguration<tbl_RoleResourcePermission>
{
    public void Configure(EntityTypeBuilder<tbl_RoleResourcePermission> builder)
    {
        builder.HasKey(a => new
        {
            a.RoleID,
            a.ResourcePermissionID
        });

        builder.HasOne(a => a.N_Role)
            .WithMany()
            .HasForeignKey(a => a.RoleID);

        builder.HasOne(a => a.N_ResourcePermission)
            .WithMany()
            .HasForeignKey(a => a.ResourcePermissionID);

        builder.HasData(GetSeedData());
    }

    tbl_RoleResourcePermission[] GetSeedData()
    {
        var list = new List<tbl_RoleResourcePermission>
        {
            #region Admin
		    new tbl_RoleResourcePermission
            {
                RoleID = 1,
                ResourcePermissionID = 1
            },
            new tbl_RoleResourcePermission
            {
                RoleID = 1,
                ResourcePermissionID = 2
            },
            new tbl_RoleResourcePermission
            {
                RoleID = 1,
                ResourcePermissionID = 3
            },
            new tbl_RoleResourcePermission
            {
                RoleID = 1,
                ResourcePermissionID = 4
            },
            new tbl_RoleResourcePermission
            {
                RoleID = 1,
                ResourcePermissionID = 5
            }, 
	        #endregion

            #region Billing
		    new tbl_RoleResourcePermission
            {
                RoleID = 2,
                ResourcePermissionID = 1
            } 
	        #endregion
        };

        return list.ToArray();
    }
}
