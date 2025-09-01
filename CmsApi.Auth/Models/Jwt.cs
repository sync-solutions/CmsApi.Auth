namespace CmsApi.Auth.Models;

public class Jwt : BaseEntity
{
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
    public DateTime AccessTokenExpiration { get; set; }
    public DateTime RefreshTokenExpiration { get; set; }
    public bool IsAccessTokenRevoked { get; set; }
    public int UserId { get; set; }
}

