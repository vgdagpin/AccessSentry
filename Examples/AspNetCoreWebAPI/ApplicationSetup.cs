using AspNetCoreWebAPI.Middlewares;

namespace AspNetCoreWebAPI;

public static class ApplicationSetup
{
    public static WebApplication TestApplicationSetup(this WebApplication app)
    {
        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI(options =>
            {
                options.EnablePersistAuthorization();
                options.EnableFilter();
                options.DefaultModelRendering(Swashbuckle.AspNetCore.SwaggerUI.ModelRendering.Model);
                options.DefaultModelsExpandDepth(-1);
                options.DocExpansion(Swashbuckle.AspNetCore.SwaggerUI.DocExpansion.None);
            });
        }

        app.UseHttpsRedirection();

        //app.UseAuthentication();
        app.UseTestAuthorization();
        app.UseAuthorization();

        app.MapControllers();

        return app;
    }

    private static void UseTestAuthorization(this WebApplication app)
    {
        app.UseMiddleware<AuthorizePermissionMiddleware>();
        app.UseMiddleware<AuthorizePolicyMiddleware>();
    }
}