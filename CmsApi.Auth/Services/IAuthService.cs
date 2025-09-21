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
    Task<AuthResponse> ValidateTokenAsync(string token);
    Task<AuthResponse> ValidateApiKeyAsync(string apiKey);
    Task<bool> ForgotPasswordAsync(ForgotPasswordRequest request);
    Task<bool> ResetPasswordAsync(ResetPasswordRequest request);
    Task<AuthResponse> RefreshTokenAsync(string refreshToken);

}
