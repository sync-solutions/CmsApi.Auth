namespace CmsApi.Auth.Models;

public abstract class BaseEntity
{
    public int Id { get; set; }
    public DateTime? CreationDate { get; set; }
    public DateTime? LastUpdateDate { get; set; }
    public int CreatedById { get; set; }
    public int LastUpdatedById { get; set; }
}
