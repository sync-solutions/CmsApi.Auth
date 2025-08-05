namespace CmsApi.Auth.Models;

public class AuthResponse
{
    public int UserId { get; set; }
    public string Username { get; set; }
    public string Email { get; set; }
    public string Token { get; set; }
    public string RefreshToken { get; set; } // Optional for now
    public DateTime Expiry { get; set; }
    public bool Success { get; set; }
    public string Message { get; set; }
}
