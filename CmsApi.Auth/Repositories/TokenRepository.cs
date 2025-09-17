using CmsApi.Auth.Data;
using CmsApi.Auth.Models;
using Microsoft.EntityFrameworkCore;
using StackExchange.Redis;
using System.Text.Json;
using CmsApi.Auth.DTOs;

namespace CmsApi.Auth.Repositories;

public class TokenRepository(AuthDbContext dbContext, IDatabase redisDB)
{
    private readonly AuthDbContext _dbContext = dbContext;
    private readonly IDatabase _redisDB = redisDB;

    public async Task<Jwt?> Get(string token)
    {
        var cacheKey = RedisKeys.AccessToken(token);
        var cached = await _redisDB.StringGetAsync(cacheKey);

        if (cached.HasValue)
            return JsonSerializer.Deserialize<Jwt>(cached);

        var jwt = await _dbContext.Jwts
            .FirstOrDefaultAsync(t => t.AccessToken == token && !t.IsAccessTokenRevoked);

        if (jwt != null)
            await CacheJwtAsync(jwt);

        return jwt;
    }

    public async Task<Jwt?> GetById(int tokenId)
    {
        var cacheKey = RedisKeys.Jwt(tokenId);
        var cached = await _redisDB.StringGetAsync(cacheKey);

        if (cached.HasValue)
            return JsonSerializer.Deserialize<Jwt>(cached);

        var jwt = await _dbContext.Jwts.FirstOrDefaultAsync(t => t.Id == tokenId);

        if (jwt != null)
            await CacheJwtAsync(jwt);

        return jwt;
    }

    public async Task<bool> RevokeToken(int jwtId)
    {
        var token = await GetById(jwtId);
        if (token == null) return false;

        token.IsAccessTokenRevoked = true;
        token.LastUpdateDate = DateTime.Now;
        await Update(token);

        await _redisDB.SetAddAsync(RedisKeys.RevokedJwt(jwtId), "1");

        await _redisDB.KeyDeleteAsync(RedisKeys.Jwt(jwtId));
        await _redisDB.KeyDeleteAsync(RedisKeys.AccessToken(token.AccessToken));

        return true;
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
            IsAccessTokenRevoked = false,
            CreationDate = DateTime.Now,
            LastUpdateDate = DateTime.Now
        };

        _dbContext.Jwts.Add(newJwt);
        await _dbContext.SaveChangesAsync();

        await CacheJwtAsync(newJwt);
        return newJwt;
    }

    public async Task<Jwt?> GetByRefreshToken(string refreshToken)
    {
        var jwt = await _dbContext.Jwts
            .FirstOrDefaultAsync(j => j.RefreshToken == refreshToken && !j.IsAccessTokenRevoked);

        if (jwt != null)
            await CacheJwtAsync(jwt);

        return jwt;
    }

    public async Task Update(Jwt jwt)
    {
        _dbContext.Jwts.Update(jwt);
        await _dbContext.SaveChangesAsync();

        await CacheJwtAsync(jwt);
    }

    private async Task CacheJwtAsync(Jwt jwt)
    {
        var serialized = JsonSerializer.Serialize(jwt);
        var expiry = TimeSpan.FromMinutes(15); // Match token lifetime

        await _redisDB.StringSetAsync(RedisKeys.Jwt(jwt.Id), serialized, expiry);
        await _redisDB.StringSetAsync(RedisKeys.AccessToken(jwt.AccessToken), serialized, expiry);
    }

    public async Task<bool> IsRevoked(int jwtId)
    {
        return await _redisDB.SetContainsAsync(RedisKeys.RevokedJwt(jwtId), "1");
    }
}
