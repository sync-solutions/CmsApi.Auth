using CmsApi.Auth.Data;
using CmsApi.Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace CmsApi.Auth.Repositories;

public class SessionRepository(AuthDbContext dbContext)
{
    public async Task<Session?> GetByIdAsync(int id)
    {
        return await dbContext.Sessions.FirstOrDefaultAsync(s => s.Id == id && s.IsActive);
    }
    public async Task<Session?> FindActiveAsync(int userId, string deviceInfo, string ipAddress)
    {
        var normalizedDeviceInfo = deviceInfo.Trim().ToLowerInvariant();
        var normalizedIpAddress = ipAddress.Trim();

        return await dbContext.Sessions
            .Include(s => s.Jwt)
            .Where(s =>
                  s.UserId == userId &&
                  s.DeviceInfo != null &&
                  s.DeviceInfo.ToLower() == normalizedDeviceInfo &&
                  s.IpAddress == normalizedIpAddress &&
                  s.IsActive &&
                  s.ExpirationDate > DateTime.Now &&
                  s.Jwt.RefreshTokenExpiration > DateTime.Now &&
                 !s.Jwt.IsAccessTokenRevoked)
            .OrderByDescending(s => s.LastActivity)
            .FirstOrDefaultAsync();
    }
    public async Task<Session?> GetByUserIdAsync(int userId)
    {
        return await dbContext.Sessions.FirstOrDefaultAsync(s => s.UserId == userId && s.IsActive);
    }
    public async Task<Session?> GetByJwtIdAsync(int id)
    {
        return await dbContext.Sessions.FirstOrDefaultAsync(s => s.JwtId == id);
    }

    public async Task AddAsync(Session session)
    {
        session.CreationDate = DateTime.Now;
        session.LastUpdateDate = DateTime.Now;
        dbContext.Sessions.Add(session);
        await dbContext.SaveChangesAsync();
    }

    public async Task UpdateAsync(Session session)
    {
        dbContext.Update(session);
        await dbContext.SaveChangesAsync();
    }

    public async Task DeleteAsync(int id)
    {
        var session = await GetByIdAsync(id);
        if (session != null)
        {
            dbContext.Sessions.Remove(session);
            await dbContext.SaveChangesAsync();
        }
    }
}

