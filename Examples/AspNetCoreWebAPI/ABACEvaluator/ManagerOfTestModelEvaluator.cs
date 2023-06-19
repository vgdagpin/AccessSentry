using AccessSentry.Interfaces;

using AspNetCoreWebAPI.AuthorizationAttributes;
using AspNetCoreWebAPI.Models;

using System.Text.Json;

namespace AspNetCoreWebAPI.ABACEvaluator;

public class ManagerOfTestModelEvaluator : IAttributePolicyEvaluator
{
    private readonly IHttpContextAccessor httpContextAccessor;
    private ManagerOfTestModelAttribute? ManagerOfTestModelAttribute;

    public ManagerOfTestModelEvaluator(IHttpContextAccessor httpContextAccessor)
    {
        this.httpContextAccessor = httpContextAccessor;
    }

    public async Task<bool> EvaluateAsync()
    {
        var httpContext = httpContextAccessor.HttpContext;
        httpContext.Request.EnableBuffering();

        // Read the request body
        using var reader = new StreamReader(httpContext.Request.Body, leaveOpen: true);
        var requestBody = await reader.ReadToEndAsync();

        // Reset the position of the request body stream for model binding
        httpContext.Request.Body.Position = 0;

        // Deserialize the JSON request body to your model object
        var model = JsonSerializer.Deserialize<TestModel>(requestBody, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

        if (model == null)
        {
            return false;
        }

        if (model.ID == 1)
        {
            return true;
        }

        return false;
    }

    public bool IsAttributeEvaluator(IAttributePolicy attributePolicy)
    {
        if (attributePolicy is ManagerOfTestModelAttribute managerOfTestModelAttribute)
        {
            ManagerOfTestModelAttribute = managerOfTestModelAttribute;

            return true;
        }

        return false;
    }
}