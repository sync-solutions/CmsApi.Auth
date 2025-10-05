namespace CmsApi.Auth.DTOs;
public class UserEditRequest
{
    public string? Name { get; set; }
    public string? MobileNumber { get; set; }
    public string? Email { get; set; }
    public int? RoleId { get; set; }
    public bool? IsActive { get; set; }
}
