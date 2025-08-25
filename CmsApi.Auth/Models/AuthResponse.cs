namespace CmsApi.Auth.Models;

public class AuthResponse
{
    public int UserId { get; set; }
    public int? SessionId { get; set; }
    public string Username { get; set; }
    public string Email { get; set; }
    public string AccessToken { get; set; }
    public DateTime AccessTokenExpiration { get; set; }
    public string RefreshToken { get; set; }
    public DateTime RefreshTokenExpiration { get; set; }
    public bool Success { get; set; }
    public string Message { get; set; }
}
