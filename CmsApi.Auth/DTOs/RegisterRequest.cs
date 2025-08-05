using System.ComponentModel.DataAnnotations;

namespace CmsApi.Auth.DTOs;

public class RegisterRequest
{
    [Required]
    [MinLength(4)]
    public string Username { get; set; }
    [Required]
    [MinLength(6)]
    public string Password { get; set; }
    [Required]
    [Compare("Password", ErrorMessage = "Password and confirmation do not match.")]
    public string ConfirmPassword { get; set; }
    [Required]
    [Phone]
    public string MobileNumber { get; set; }
    [Required]
    [EmailAddress]
    public string Email { get; set; }
    [Required]
    [StringLength(100, MinimumLength = 3)]
    public string Name { get; set; }
    [Required]
    public int RoleId { get; set; }
}
