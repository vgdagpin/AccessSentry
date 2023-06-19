using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AccessSentry.EFCorePolicyProvider.Entities;

public partial class tbl_Resource : IEntityTypeConfiguration<tbl_Resource>
{
    public void Configure(EntityTypeBuilder<tbl_Resource> builder)
    {
        builder.HasOne(a => a.N_ParentResource)
            .WithMany()
            .HasForeignKey(a => a.ParentResourceID);

        builder.HasData(GetSeedData());
    }

    tbl_Resource[] GetSeedData()
    {
        var list = new List<tbl_Resource>
        {
            new tbl_Resource
            {
                ResourceID = 1,
                Name = "Organization",
                Description = "Organization"
            },

            new tbl_Resource
            {
                ResourceID = 2,
                Name = "Contact",
                Description = "Organization Contact",
                ParentResourceID = 1
            }
        };

        return list.ToArray();
    }
}
