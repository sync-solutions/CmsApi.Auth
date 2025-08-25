using CmsApi.Auth.Models;
using CmsApi.Auth.Repositories;

namespace CmsApi.Auth.Services;

public class SessionService(SessionRepository sessionRepository)
{
    private readonly SessionRepository _sessionRepository = sessionRepository;

    public async Task<Session> CreateSessionAsync(Session session)
    {
        await _sessionRepository.AddAsync(session);
        return session;
    }
    public async Task<Session?> GetSessionAsync(int sessionId)
    {
        return await _sessionRepository.GetByIdAsync(sessionId);
    }
    public async Task<bool> RefreshSessionAsync(int sessionId)
    {
        var session = await _sessionRepository.GetByIdAsync(sessionId);

        if (session == null)
            return false;

        if (!session.IsActive)
            return false;

        session.LastActivity = DateTime.Now;

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
    public async Task<bool> EndSessionAsync(int sessionId)
    {
        var session = await _sessionRepository.GetByIdAsync(sessionId);
        if (session == null)
            return false;

        session.IsActive = false;
        await _sessionRepository.UpdateAsync(session);
        return true;
    }
    public async Task<bool> IsSessionActiveAsync(int sessionId)
    {
        var session = await _sessionRepository.GetByIdAsync(sessionId);
        return session != null && session.IsActive && session.LastActivity > DateTime.Now.AddMinutes(-30);
    }
}
