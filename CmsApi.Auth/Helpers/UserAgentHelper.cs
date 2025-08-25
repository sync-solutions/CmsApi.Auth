using UAParser;

namespace CmsApi.Auth.Helpers;

public static class UserAgentHelper
{
    private static readonly Parser _uaParser = Parser.GetDefault();

    public static string GetOSFromUserAgent(string userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent)) return "Unknown OS";
        var clientInfo = _uaParser.Parse(userAgent);
        return $"{clientInfo.OS.Family} {clientInfo.OS.Major}".Trim();
    }

    public static string GetBrowserFromUserAgent(string userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent)) return "Unknown Browser";
        var clientInfo = _uaParser.Parse(userAgent);
        return $"{clientInfo.UA.Family} {clientInfo.UA.Major}".Trim();
    }
}
