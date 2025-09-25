namespace CmsApi.Auth.Models;

public class ApiKey : BaseEntity
{
    public string Key { get; set; }
    public string Name { get; set; }
    public string UserName { get; set; }
    public int UserId { get; set; }
    public string Owner { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.Now;  
    public DateTime? ExpiresAt { get; set; }
    public bool IsActive { get; set; } = true;
}
