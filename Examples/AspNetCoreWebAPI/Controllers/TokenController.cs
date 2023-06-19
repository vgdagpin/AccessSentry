using AspNetCoreWebAPI.Common;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AspNetCoreWebAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class TokenController : ControllerBase
{
    private readonly IHostEnvironment environment;
    private readonly TokenValidationParameters tokenValidationParameters;
    private readonly IConfiguration configuration;

    public TokenController(IHostEnvironment environment, TokenValidationParameters tokenValidationParameters, IConfiguration configuration)
    {
        this.environment = environment;
        this.tokenValidationParameters = tokenValidationParameters;
        this.configuration = configuration;
    }

    [HttpGet]
    [Route("Generate")]
    [AllowAnonymous]
    public string Generate(string roles)
    {
        if (!environment.IsDevelopment())
        {
            return null;
        }

        var jwtConfig = new JwtConfiguration();

        configuration.Bind("Jwt", jwtConfig);

        var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtConfig.SecurityKey));
        var signingCred = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenExpiration = DateTime.UtcNow.AddSeconds(jwtConfig.TokenExpirationInSeconds);
        var roleClaims = new List<Claim>();

        foreach (var role in roles.Split(','))
        {
            roleClaims.Add(new Claim(ClaimTypes.Role, role));
        }

        var token = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(roleClaims),
            Issuer = jwtConfig.Issuer,
            Audience = jwtConfig.Audience,
            IssuedAt = DateTime.UtcNow,
            NotBefore = DateTime.UtcNow,
            Expires = tokenExpiration,
            SigningCredentials = signingCred
        };

        var securityToken = tokenHandler.CreateToken(token);

        var tokenResult = tokenHandler.WriteToken(securityToken);

        tokenHandler.ValidateToken(tokenResult, tokenValidationParameters, out var res);

        return tokenResult;
    }
}
