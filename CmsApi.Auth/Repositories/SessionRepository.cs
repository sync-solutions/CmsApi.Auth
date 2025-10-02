using CmsApi.Auth.Data;
using CmsApi.Auth.Models;
using CmsApi.Auth.DTOs;
using Microsoft.EntityFrameworkCore;
using StackExchange.Redis;
using System.Text.Json;

namespace CmsApi.Auth.Repositories;

public class SessionRepository(AuthDbContext dbContext, IDatabase redisDB)
{
    private readonly AuthDbContext _dbContext = dbContext;
    private readonly IDatabase _redisDB = redisDB;

    public async Task<Session?> GetByIdAsync(int id)
    {
        var cacheKey = RedisKeys.Session(id);
        var cached = await _redisDB.StringGetAsync(cacheKey);

        if (cached.HasValue)
            return JsonSerializer.Deserialize<Session>(cached);

        var session = await _dbContext.Sessions.Include(s => s.Jwt)
            .FirstOrDefaultAsync(s => s.Id == id && s.IsActive);

        if (session != null)
            await CacheSessionAsync(session);

        return session;
    }
    public async Task<Session?> FindActiveAsync(int userId, string deviceInfo, string ipAddress)
    {
        var cacheKey = RedisKeys.ActiveSessionKey(userId, deviceInfo, ipAddress);
        var cached = await _redisDB.StringGetAsync(cacheKey);

        if (cached.HasValue)
            return JsonSerializer.Deserialize<Session>(cached);

        var normalizedDeviceInfo = deviceInfo.Trim().ToLowerInvariant();
        var normalizedIpAddress = ipAddress.Trim();

        var session = await _dbContext.Sessions
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

        if (session != null)
            await CacheSessionAsync(session, cacheKey);

        return session;
    }
    public async Task<Session?> GetByUserIdAsync(int userId)
    {
        var cacheKey = RedisKeys.SessionByUser(userId);
        var cached = await _redisDB.StringGetAsync(cacheKey);

        if (cached.HasValue)
            return JsonSerializer.Deserialize<Session>(cached);

        var session = await _dbContext.Sessions
            .Include(s => s.Jwt)
            .FirstOrDefaultAsync(s => s.UserId == userId && s.IsActive);

        if (session != null)
            await CacheSessionAsync(session, cacheKey);

        return session;
    }
    public async Task<Session?> GetByJwtIdAsync(int jwtId)
    {
        var cacheKey = RedisKeys.SessionByJwt(jwtId);
        var cached = await _redisDB.StringGetAsync(cacheKey);

        if (cached.HasValue)
            return JsonSerializer.Deserialize<Session>(cached);

        var session = await _dbContext.Sessions
            .Include(s => s.Jwt)
            .FirstOrDefaultAsync(s => s.JwtId == jwtId);

        if (session != null)
            await CacheSessionAsync(session);

        return session;
    }
    public async Task AddAndCacheAsync(Session session)
    {
        session.CreationDate = DateTime.Now;
        session.LastUpdateDate = DateTime.Now;

        _dbContext.Sessions.Add(session);
        await _dbContext.SaveChangesAsync();

        await CacheSessionAsync(session);
    }
    public async Task AddAsync(Session session)
    {
        session.CreationDate = DateTime.Now;
        session.LastUpdateDate = DateTime.Now;

        _dbContext.Sessions.Add(session);
        await _dbContext.SaveChangesAsync();

    }
    public async Task UpdateAsync(Session session)
    {
        session.LastUpdateDate = DateTime.Now;

        _dbContext.Update(session);
        await _dbContext.SaveChangesAsync();

        await CacheSessionAsync(session);
    }
    public async Task DeleteAsync(int id)
    {
        var session = await GetByIdAsync(id);
        if (session != null)
        {
            _dbContext.Sessions.Remove(session);
            await _dbContext.SaveChangesAsync();

            await _redisDB.KeyDeleteAsync(RedisKeys.Session(id));
            await _redisDB.KeyDeleteAsync(RedisKeys.SessionByJwt(session.JwtId.Value));
            await _redisDB.KeyDeleteAsync(RedisKeys.SessionByUser(session.UserId));
            await _redisDB.KeyDeleteAsync(RedisKeys.ActiveSessionKey(session.UserId, session.DeviceInfo, session.IpAddress));
        }
    }
    public async Task CacheSessionAsync(Session session, string? overrideKey = null)
    {
        var serialized = JsonSerializer.Serialize(session);
        var expiry = TimeSpan.FromHours(1);

        await _redisDB.StringSetAsync(RedisKeys.Session(session.Id), serialized, expiry);
        if (session.JwtId != null)
            await _redisDB.StringSetAsync(RedisKeys.SessionByJwt(session.JwtId.Value), serialized, expiry);
        await _redisDB.StringSetAsync(RedisKeys.SessionByUser(session.UserId), serialized, expiry);
        await _redisDB.StringSetAsync(RedisKeys.ActiveSessionKey(session.UserId, session.DeviceInfo, session.IpAddress), serialized, expiry);

        if (!string.IsNullOrWhiteSpace(overrideKey))
            await _redisDB.StringSetAsync(overrideKey, serialized, expiry);
    }
}
