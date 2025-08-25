namespace CmsApi.Auth.Models;

public class Session : BaseEntity
{
    public string DeviceInfo { get; set; }
    public string UserAgent { get; set; }
    public string IpAddress { get; set; }
    public string Token { get; set; }
    public string RefreshToken { get; set; }
    public DateTime RefreshTokenExpiry { get; set; }
    public DateTime? RevokedAt { get; set; }
    public DateTime ExpirationDate { get; set; }
    public DateTime LastActivity { get; set; }
    public bool IsActive { get; set; }
    public int UserId { get; set; }
}
