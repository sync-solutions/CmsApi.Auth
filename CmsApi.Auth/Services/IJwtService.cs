using CmsApi.Auth.Models;
using System.Security.Claims;

namespace CmsApi.Auth.Services;
public interface IJwtService
{
    string GenerateToken(User user);
    string GenerateRefreshToken();
    ClaimsPrincipal? ValidateToken(string token);
}
