using CmsApi.Auth.DTOs;
using CmsApi.Auth.Models;
using System.Security.Claims;

namespace CmsApi.Auth.Services;

public interface IAuthService
{
    Task<AuthResponse> LoginAsync(LoginRequest request);
    Task<AuthResponse> GoogleLoginAsync(User user);
    Task<AuthResponse> LogoutAsync(ClaimsPrincipal User);
    Task<AuthResponse> RegisterAsync(RegisterRequest request);
    Task<AuthResponse> ValidateApiKeyAsync(string apiKey);

}
