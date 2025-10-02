namespace CmsApi.Auth.DTOs;

public class SetPasswordRequest
{
    public string Email { get; set; }
    public string NewPassword { get; set; }
}
