using CmsApi.Auth.Data;
using CmsApi.Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace CmsApi.Auth.Repositories;

public class TokenRepository(AuthDbContext dbContext)

{
    public async Task<Jwt?> Get(string token)
    {
        return await dbContext.Jwts
            .FirstOrDefaultAsync(t => t.AccessToken == token && !t.IsAccessTokenRevoked);
    }
    public async Task<Jwt> RevokeToken(Jwt jwtRecord)
    {
        dbContext.Attach(jwtRecord);
        jwtRecord.IsAccessTokenRevoked = true;
        dbContext.Entry(jwtRecord).Property(j => j.IsAccessTokenRevoked).IsModified = true;
        await dbContext.SaveChangesAsync();
        return jwtRecord;
    }
    public async Task<Jwt> Add(string refreshToken, User newUser, string accessToken)
    {
        var newJwt = new Jwt
        {
            UserId = newUser.Id,
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            AccessTokenExpiration = DateTime.Now.AddMinutes(15),
            RefreshTokenExpiration = DateTime.Now.AddDays(7),
            IsAccessTokenRevoked = false
        };
        dbContext.Jwts.Add(newJwt);
        await dbContext.SaveChangesAsync();
        return newJwt;
    }
    public Task<Jwt?> GetByRefreshToken(string refreshToken)
    {
        return dbContext.Jwts
                    .FirstOrDefaultAsync(j => j.RefreshToken == refreshToken && !j.IsAccessTokenRevoked);
    }
    public async Task Update(Jwt jwt)
    {
        dbContext.Jwts.Update(jwt);
        await dbContext.SaveChangesAsync();
    }
}
