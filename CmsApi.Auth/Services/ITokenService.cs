using CmsApi.Auth.Models;
using System.Security.Claims;

namespace CmsApi.Auth.Services;
public interface ITokenService
{
    string GenerateToken(User user, int sessionId);
    string GenerateRefreshToken();
    ClaimsPrincipal? ValidateToken(string token);
    Task<AuthResponse> GetTokenValidationResponse(string token);
    Task<bool> RevokeToken(int tokenId);
    Task<AuthResponse> RefreshTokenAsync(string refreshToken);
}
