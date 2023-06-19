#region Usings
using AccessSentry;
using AccessSentry.EFCorePolicyProvider;
using AccessSentry.Interfaces;
using AccessSentry.PermissionProviders.Casbin;

using AspNetCoreWebAPI.ABACEvaluator;
using AspNetCoreWebAPI.Common;
using AspNetCoreWebAPI.PermissionProviders;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

using System.Reflection;
using System.Text;

#endregion
namespace AspNetCoreWebAPI;

public static class ApplicationServices
{
    public static WebApplicationBuilder TestApplicationServices(this WebApplicationBuilder builder)
    {
        var services = builder.Services;
        var configuration = builder.Configuration;
        var environment = builder.Environment;

        services.AddControllers(options =>
        {
            var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();

            options.Filters.Add(new AuthorizeFilter(policy));
        });

        #region Swagger
        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(option =>
        {
            option.SwaggerDoc("v1", new OpenApiInfo { Title = "Authorization API", Version = "v1" });
            option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                In = ParameterLocation.Header,
                Name = "Authorization",
                Type = SecuritySchemeType.ApiKey,
                BearerFormat = "JWT",
                Scheme = "Bearer"

            });

            option.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type=ReferenceType.SecurityScheme,
                            Id="Bearer"
                        }
                    },
                    new string[]{}
                }
            });
        }); 
        #endregion

        var jwtConfig = new JwtConfiguration();

        configuration.Bind("Jwt", jwtConfig);

        services.AddTestAuthentication(environment, jwtConfig);
        services.AddTestAuthorization(configuration);

        return builder;
    }

    static IServiceCollection AddTestAuthentication(this IServiceCollection services, IHostEnvironment environment, params JwtConfiguration[] jwtConfigurations)
    {
        var tokenValidationParameter = new TokenValidationParameters()
        {
            ValidateLifetime = true,
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,

            ValidIssuers = jwtConfigurations.Select(a => a.Issuer).ToArray(),
            ValidAudiences = jwtConfigurations.Select(a => a.Audience).ToArray(),
            ClockSkew = TimeSpan.Zero,

            IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
            {
                var secKey = new List<SecurityKey>();

                var config = jwtConfigurations.SingleOrDefault(a => a.Issuer == securityToken.Issuer);
                if (config != null)
                {
                    secKey.Add(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(config.SecurityKey)));
                }

                return secKey;
            }
        };

        if (environment.IsDevelopment())
        {
            tokenValidationParameter.ValidateLifetime = false;
            tokenValidationParameter.ValidateAudience = false;
            tokenValidationParameter.ValidateIssuer = false;
            tokenValidationParameter.ValidateIssuerSigningKey = false;
        }

        services.AddSingleton(tokenValidationParameter);

        services.AddAuthentication(sharedOptions => sharedOptions.DefaultScheme = JwtBearerDefaults.AuthenticationScheme)
           .AddJwtBearer(options => options.TokenValidationParameters = tokenValidationParameter);

        return services;
    }

    static IServiceCollection AddTestAuthorization(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHttpContextAccessor();

        services.AddScoped<IAccessSentryAuthorizationService>(sp =>
        {
            var permProviderFactory = sp.GetService<IPermissionProviderFactory>();
            var httpContextAccessor = sp.GetService<IHttpContextAccessor>();

            return new AccessSentryAuthorizationService(permProviderFactory, httpContextAccessor.HttpContext.User);
        });

        #region Permission Provider
        services.AddScoped<IPolicyProvider, EFPolicyProvider>();

        services.AddScoped<IPermissionProvider, CasbinPermissionProvider>();
        services.AddScoped<IPermissionProvider, CasbinFuncPermissionProvider>();
        services.AddScoped<IPermissionProvider, CasbinRequestAuthorizationProvider>();
        services.AddScoped<IPermissionProvider, RBACPermissionProvider>();

        services.AddScoped<IPermissionProviderFactory, PermissionProviderFactory>();
        #endregion

        #region Policy Evaluator
        services.AddScoped<IAttributePolicyEvaluator, ManagerOfTestModelEvaluator>();

        services.AddScoped<IPolicyEvaluatorFactory, PolicyEvaluatorFactory>(); 
        #endregion

        services.AddDbContext<AccessSentryDbContext>(options =>
        {
            options.UseSqlServer
            (
                connectionString: configuration.GetConnectionString("AccessSentryDbContext_ConStr"),
                sqlServerOptionsAction: opt =>
                {
                    opt.MigrationsAssembly(Assembly.GetExecutingAssembly().FullName);
                    opt.MigrationsHistoryTable("tbl_MigrationHistory", "adm");
                }
            );
        });

        services.AddAuthorization();

        return services;
    }
}