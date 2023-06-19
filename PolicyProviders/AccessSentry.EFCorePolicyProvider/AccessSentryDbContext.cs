using AccessSentry.EFCorePolicyProvider.Entities;

using Microsoft.EntityFrameworkCore;

namespace AccessSentry.EFCorePolicyProvider;

public class AccessSentryDbContext : DbContext
{
    public DbSet<tbl_Role> Roles { get; set; }
    public DbSet<tbl_Resource> Resources { get; set; }
    public DbSet<tbl_ResourcePermission> ResourcePermission { get; set; }
    public DbSet<tbl_RoleResourcePermission> RoleResourcePermissions { get; set; }

    public AccessSentryDbContext(DbContextOptions dbContextOpt) : base(dbContextOpt) 
    {
        Database.Migrate();
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AccessSentryDbContext).Assembly);

        
    }

}