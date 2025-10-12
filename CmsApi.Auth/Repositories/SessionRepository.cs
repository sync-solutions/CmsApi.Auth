using CmsApi.Auth.Data;
using CmsApi.Auth.Models;
using CmsApi.Auth.DTOs;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using System;

namespace CmsApi.Auth.Repositories;

public class SessionRepository(AuthDbContext dbContext, IMemoryCache memoryCache)
{
    private readonly AuthDbContext _dbContext = dbContext;
    private readonly IMemoryCache _memoryCache = memoryCache;

    public async Task<Session?> GetByIdAsync(int id)
    {
        var cacheKey = CacheKeys.Session(id);
        if (_memoryCache.TryGetValue(cacheKey, out Session cached))
            return cached;

        var session = await _dbContext.Sessions.Include(s => s.Jwt)
            .FirstOrDefaultAsync(s => s.Id == id && s.IsActive);

        if (session != null)
            CacheSession(session);

        return session;
    }

    public async Task<Session?> FindActiveAsync(int userId, string deviceInfo, string ipAddress)
    {
        var cacheKey = CacheKeys.ActiveSessionKey(userId, deviceInfo, ipAddress);
        if (_memoryCache.TryGetValue(cacheKey, out Session cached))
            return cached;

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
            CacheSession(session, cacheKey);

        return session;
    }
    public async Task<Session?> GetByUserIdAsync(int userId)
    {
        var cacheKey = CacheKeys.SessionByUser(userId);
        if (_memoryCache.TryGetValue(cacheKey, out Session cached))
            return cached;

        var session = await _dbContext.Sessions
            .Include(s => s.Jwt)
            .FirstOrDefaultAsync(s => s.UserId == userId && s.IsActive);

        if (session != null)
            CacheSession(session, cacheKey);

        return session;
    }
    public async Task<Session?> GetByJwtIdAsync(int jwtId)
    {
        var cacheKey = CacheKeys.SessionByJwt(jwtId);
        if (_memoryCache.TryGetValue(cacheKey, out Session cached))
            return cached;

        var session = await _dbContext.Sessions
            .Include(s => s.Jwt)
            .FirstOrDefaultAsync(s => s.JwtId == jwtId);

        if (session != null)
            CacheSession(session);

        return session;
    }
    public async Task AddAndCacheAsync(Session session)
    {
        session.CreationDate = DateTime.Now;
        session.LastUpdateDate = DateTime.Now;

        _dbContext.Sessions.Add(session);
        await _dbContext.SaveChangesAsync();

        CacheSession(session);
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
        _dbContext.Entry(session).Property(s => s.IsActive).IsModified = true;
        _dbContext.Entry(session).Property(s => s.RevokedAt).IsModified = true;
        _dbContext.Entry(session).Property(s => s.LastUpdateDate).IsModified = true;

        await _dbContext.SaveChangesAsync();
        CacheSession(session);
    }
    public async Task DeleteAsync(int id)
    {
        var session = await GetByIdAsync(id);
        if (session != null)
        {
            _dbContext.Sessions.Remove(session);
            await _dbContext.SaveChangesAsync();

            _memoryCache.Remove(CacheKeys.Session(id));
            if (session.JwtId != null)
                _memoryCache.Remove(CacheKeys.SessionByJwt(session.JwtId.Value));
            _memoryCache.Remove(CacheKeys.SessionByUser(session.UserId));
            _memoryCache.Remove(CacheKeys.ActiveSessionKey(session.UserId, session.DeviceInfo, session.IpAddress));
        }
    }
    public void CacheSession(Session session, string? overrideKey = null)
    {
        var expiry = TimeSpan.FromHours(1);

        _memoryCache.Set(CacheKeys.Session(session.Id), session, expiry);

        if (session.JwtId != null)
            _memoryCache.Set(CacheKeys.SessionByJwt(session.JwtId.Value), session, expiry);

        _memoryCache.Set(CacheKeys.SessionByUser(session.UserId), session, expiry);
        _memoryCache.Set(CacheKeys.ActiveSessionKey(session.UserId, session.DeviceInfo, session.IpAddress), session, expiry);

        if (!string.IsNullOrWhiteSpace(overrideKey))
            _memoryCache.Set(overrideKey, session, expiry);
    }
}