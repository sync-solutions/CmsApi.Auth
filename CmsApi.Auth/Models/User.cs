namespace CmsApi.Auth.Models;

public class User : BaseEntity
{
    public string Name { get; set; }
    public string Username { get; set; }
    public string? EncPassword { get; set; }
    public string Email { get; set; }
    public string MobileNumber { get; set; }
    public int RoleId { get; set; }
    public bool IsActive { get; set; }
    public string? ResetPassToken { get; set; }
    public string? Provider { get; set; }
    public DateTime? ResetPassTokenExpiry { get; set; }

}
