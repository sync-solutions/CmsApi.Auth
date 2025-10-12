using CmsApi.Auth.Data;
using CmsApi.Auth.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using CmsApi.Auth.DTOs;
using StackExchange.Redis;

namespace CmsApi.Auth.Repositories;

public class TokenRepository(AuthDbContext dbContext, IMemoryCache memoryCache)
{
    private readonly AuthDbContext _dbContext = dbContext;
    private readonly IMemoryCache _memoryCache = memoryCache;

    public async Task<Jwt?> Get(string token)
    {
        var cacheKey = CacheKeys.AccessToken(token);
        if (_memoryCache.TryGetValue(cacheKey, out Jwt cached))
            return cached;

        var jwt = await _dbContext.Jwts
            .FirstOrDefaultAsync(t => t.AccessToken == token && !t.IsAccessTokenRevoked);

        if (jwt != null)
            CacheJwt(jwt);

        return jwt;
    }

    public async Task<Jwt?> GetById(int tokenId)
    {
        var cacheKey = CacheKeys.Jwt(tokenId);
        if (_memoryCache.TryGetValue(cacheKey, out Jwt cached))
            return cached;

        var jwt = await _dbContext.Jwts.FirstOrDefaultAsync(t => t.Id == tokenId);

        if (jwt != null)
            CacheJwt(jwt);

        return jwt;
    }

    public async Task<bool> RevokeToken(int jwtId)
    {
        var token = await GetById(jwtId);
        if (token == null) return false;

        token.IsAccessTokenRevoked = true;
        token.LastUpdateDate = DateTime.Now;
        await Update(token);

        _memoryCache.Set(CacheKeys.RevokedJwt(jwtId), true, TimeSpan.FromDays(7)); // configurable TTL
        _memoryCache.Remove(CacheKeys.Jwt(jwtId));
        _memoryCache.Remove(CacheKeys.AccessToken(token.AccessToken));

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

        CacheJwt(newJwt);
        return newJwt;
    }

    public async Task<Jwt?> GetByRefreshToken(string refreshToken)
    {
        var jwt = await _dbContext.Jwts
            .FirstOrDefaultAsync(j => j.RefreshToken == refreshToken && !j.IsAccessTokenRevoked);

        if (jwt != null)
            CacheJwt(jwt);

        return jwt;
    }

    public async Task Update(Jwt jwt)
    {
        _dbContext.Jwts.Update(jwt);
        await _dbContext.SaveChangesAsync();

        CacheJwt(jwt);
    }

    private void CacheJwt(Jwt jwt)
    {
        var expiry = TimeSpan.FromMinutes(15);

        _memoryCache.Set(CacheKeys.Jwt(jwt.Id), jwt, expiry);
        _memoryCache.Set(CacheKeys.AccessToken(jwt.AccessToken), jwt, expiry);
    }

    public Task<bool> IsRevoked(int jwtId)
    {
        return Task.FromResult(_memoryCache.TryGetValue(CacheKeys.RevokedJwt(jwtId), out _));
    }
}