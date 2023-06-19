namespace AspNetCoreWebAPI.Common;

public class JwtConfiguration
{
    public string Audience { get; set; }
    public string Issuer { get; set; }
    public string SecurityKey { get; set; }
    public int TokenExpirationInSeconds { get; set; }
}