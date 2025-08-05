namespace CmsApi.Auth.Models;
public class Jwt
{
    public int Id { get; set; }
    public string Token { get; set; }
    public string Jti { get; set; }
    public DateTime IssuedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public bool IsRevoked { get; set; } = false;

    public string IpAddress { get; set; }
    public string UserAgent { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string RevokedBy { get; set; }
    public int UserId { get; set; }
}
