namespace CmsApi.Auth.Models;

public class Session
{
    public int Id { get; set; }
    public string Token { get; set; }
    public string SessionId { get; set; }
    public DateTime ExpirationDate { get; set; }
    public int UserId { get; set; }
    public DateTime? CreationDate { get; set; }
    public DateTime? LastUpdateDate { get; set; }
    public int CreatedById { get; set; }
    public int LastUpdatedById { get; set; }
}
