using CmsApi.Auth.Data;
using CmsApi.Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace CmsApi.Auth.Repositories;

public class SessionRepository(AuthDbContext dbContext)
{
    public async Task<Session?> GetByIdAsync(int id)
    {
        return await dbContext.Sessions.FirstOrDefaultAsync(s => s.Id == id);
    }

    public async Task<Session?> GetByUserIdAsync(int userId)
    {
        return await dbContext.Sessions.FirstOrDefaultAsync(s => s.UserId == userId);
    }

    public async Task AddAsync(Session session)
    {
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

