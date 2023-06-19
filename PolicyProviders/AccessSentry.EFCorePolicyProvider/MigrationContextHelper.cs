using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

using System.Reflection;

namespace AccessSentry.EFCorePolicyProvider;

class MigrationContextHelper : IDesignTimeDbContextFactory<AccessSentryDbContext>
{
    public AccessSentryDbContext CreateDbContext(string[] args)
    {
        var config = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json")
            .Build();

        var dbContextOptBuilder = new DbContextOptionsBuilder()
            .UseSqlServer
            (
                connectionString: config.GetConnectionString("AccessSentryDbContext_ConStr"),
                sqlServerOptionsAction: opt =>
                {
                    opt.MigrationsAssembly(Assembly.GetExecutingAssembly().FullName);
                    opt.MigrationsHistoryTable("tbl_MigrationHistory", "adm");
                }
            );

        return new AccessSentryDbContext(dbContextOptBuilder.Options);
    }
}