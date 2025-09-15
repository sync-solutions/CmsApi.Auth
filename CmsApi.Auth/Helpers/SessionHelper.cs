using CmsApi.Auth.Models;

namespace CmsApi.Auth.Helpers;

public class SessionHelper(IHttpContextAccessor httpContextAccessor)
{
    public Session CreateNew(User user)
    {
        var httpContext = httpContextAccessor.HttpContext;

        var userAgent = httpContext?.Request.Headers["User-Agent"].ToString()?.Trim() ?? string.Empty;

        var os = UserAgentHelper.GetOSFromUserAgent(userAgent);
        var browser = UserAgentHelper.GetBrowserFromUserAgent(userAgent);
        var deviceInfo = $"{os}, {browser}".Trim().ToLowerInvariant();

        var ipAddress = httpContext?.Connection?.RemoteIpAddress?.ToString()?.Trim() ?? "unknown";

        var session = new Session
        {
            UserId = user.Id,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            DeviceInfo = deviceInfo,
            LastActivity = DateTime.Now,
            IsActive = true,
            ExpirationDate = DateTime.Now.AddHours(1)
        };

        return session;
    }

}
