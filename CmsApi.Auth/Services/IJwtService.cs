using CmsApi.Auth.Models;
using System.Security.Claims;

namespace CmsApi.Auth.Services;
public interface IJwtService
{
    string GenerateToken(User user, int sessionId);
    string GenerateRefreshToken();
    ClaimsPrincipal? ValidateToken(string token);
    Task<bool> RevokeToken(int tokenId);
}
