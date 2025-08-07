using CmsApi.Auth.DTOs;
using CmsApi.Auth.Models;

namespace CmsApi.Auth.Services;

public interface IAuthService
{
    Task<AuthResponse> LoginAsync(LoginRequest request);
    Task<bool> LogoutAsync(string token);
    Task<AuthResponse> RegisterAsync(RegisterRequest request);
    Task<AuthResponse> ValidateTokenAsync(string token);
    Task<AuthResponse> ValidateApiKeyAsync(string apiKey);
    Task<bool> ForgotPasswordAsync(ForgotPasswordRequest request);
    Task<bool> ResetPasswordAsync(ResetPasswordRequest request);
    Task<AuthResponse> RefreshTokenAsync(string refreshToken);

}
