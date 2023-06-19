using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AccessSentry.EFCorePolicyProvider.Entities;

public partial class tbl_Role : IEntityTypeConfiguration<tbl_Role>
{
    public void Configure(EntityTypeBuilder<tbl_Role> builder)
    {
        builder.HasData(GetSeedData());
    }

    tbl_Role[] GetSeedData()
    {
        var list = new List<tbl_Role>
        {
            new tbl_Role
            {
                RoleID = 1,
                Name = "Admin",
                Description = "Admin"
            },
            new tbl_Role
            {
                RoleID = 2,
                Name = "Billing",
                Description = "Billing"
            }
        };

        return list.ToArray();
    }
}
