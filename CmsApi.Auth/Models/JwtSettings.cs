namespace CmsApi.Auth.Models;

public class JwtSettings
{
    public string Key { get; set; } = null!;
    public string Issuer { get; set; } = null!;
    public string Audience { get; set; } = null!;
    public int AccessTokenExpiryMins { get; set; }
    public int RefreshTokenExpiryDays { get; set; }
}
