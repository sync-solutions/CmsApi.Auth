namespace CmsApi.Auth.DTOs;

public class CacheKeys
{
    public static string Session(int sessionId) => $"session:{sessionId}";
    public static string SessionByJwt(int jwtId) => $"session:jwt:{jwtId}";
    public static string SessionByUser(int userId) => $"session:user:{userId}";

    public static string RevokedToken(string tokenId) => $"revoked:token:{tokenId}";
    public static string RevokedJwt(int jwtId) => $"revoked:jwt:{jwtId}";

    public static string ActiveSessionKey(int userId, string deviceInfo, string ipAddress)
    {
        var normalizedDevice = deviceInfo.Trim().ToLowerInvariant();
        var normalizedIp = ipAddress.Trim();
        return $"session:active:{userId}:{normalizedDevice}:{normalizedIp}";
    }
    public static string RefreshToken(string token) => $"refresh:{token}";
    public static string AccessToken(string token) => $"jwt:access:{token}";
    public static string Jwt(int jwtId) => $"jwt:{jwtId}";
}
