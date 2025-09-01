using CmsApi.Auth.Models;

namespace CmsApi.Auth.Helpers;

public class SessionHelper(IHttpContextAccessor httpContextAccessor)
{
    public Session CreateNew(User user, Jwt newJwt)
    {
        var userAgent = httpContextAccessor.HttpContext?.Request.Headers["User-Agent"].ToString();
        var ipAddress = httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString();

        var deviceInfo = $"{UserAgentHelper.GetOSFromUserAgent(userAgent)}, {UserAgentHelper.GetBrowserFromUserAgent(userAgent)}";

        var session = new Session
        {
            UserId = user.Id,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            DeviceInfo = deviceInfo,
            LastActivity = DateTime.Now,
            IsActive = true,
            JwtId = newJwt.Id,
            ExpirationDate = DateTime.Now.AddHours(1)
        };
        return session;
    }

}
