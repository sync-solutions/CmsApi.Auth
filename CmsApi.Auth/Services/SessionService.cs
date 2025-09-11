using CmsApi.Auth.Models;
using CmsApi.Auth.Repositories;
using Microsoft.EntityFrameworkCore;

namespace CmsApi.Auth.Services;

public class SessionService(SessionRepository sessionRepository)
{
    private readonly SessionRepository _sessionRepository = sessionRepository;

    public async Task<Session> CreateAsync(Session session)
    {
        await _sessionRepository.AddAsync(session);
        return session;
    }
    public async Task<Session?> GetByIdAsync(int id)
    {
        return await _sessionRepository.GetByIdAsync(id);
    }
    public async Task<Session?> GetByUserIdAsync(int userId)
    {
        return await _sessionRepository.GetByUserIdAsync(userId);
    }
    public async Task<Session?> GetAsync(int sessionId)
    {
        return await _sessionRepository.GetByIdAsync(sessionId);
    }
    public async Task<Session?> FindActiveAsync(int userId, string deviceInfo, string ipAddress)
    {
        return await _sessionRepository.FindActiveAsync(userId, deviceInfo, ipAddress);
    }
    public async Task<bool> RefreshAsync(int sessionId)
    {
        var session = await _sessionRepository.GetByIdAsync(sessionId);

        if (session == null)
            return false;

        if (!session.IsActive)
            return false;

        session.LastActivity = DateTime.Now;
        session.LastUpdateDate = DateTime.Now;

        try
        {
            await _sessionRepository.UpdateAsync(session);
            return true;
        }
        catch
        {
            return false;
        }
    }
    public async Task<bool> EndAsync(int sessionId)
    {
        var session = await _sessionRepository.GetByIdAsync(sessionId);
        if (session == null)
            return false;

        session.IsActive = false;
        session.LastUpdateDate = DateTime.Now;
        await _sessionRepository.UpdateAsync(session);
        return true;
    }
    public async Task<bool> IsActiveAsync(int sessionId)
    {
        var session = await _sessionRepository.GetByIdAsync(sessionId);
        return session != null && session.IsActive && session.LastActivity > DateTime.Now.AddMinutes(-30);
    }
    public async Task AttachJwtAsync(int sessionId, Jwt jwt)
    {
        var session = await _sessionRepository.GetByIdAsync(sessionId) ??
                      throw new InvalidOperationException($"Session {sessionId} not found.");

        session.JwtId = jwt.Id;
        session.Jwt = jwt;

        await _sessionRepository.UpdateAsync(session);
    }

}
