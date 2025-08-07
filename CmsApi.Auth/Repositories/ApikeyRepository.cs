using CmsApi.Auth.Data;
using CmsApi.Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace CmsApi.Auth.Repositories
{
    public class ApikeyRepository(AuthDbContext dbContext)
    {
        public async Task<ApiKey?> GetValid(string apiKey)
        {
            return await dbContext.ApiKeys
                .FirstOrDefaultAsync(k =>
                    k.Key == apiKey &&
                    k.IsActive &&
                    (k.ExpiresAt == null || k.ExpiresAt > DateTime.Now));
        }
    }
}
