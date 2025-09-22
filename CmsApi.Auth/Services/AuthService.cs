using Azure.Core;
using CmsApi.Auth.DTOs;
using CmsApi.Auth.Helpers;
using CmsApi.Auth.Models;
using CmsApi.Auth.Repositories;
using System.Security.Claims;

namespace CmsApi.Auth.Services;

public class AuthService(
    TokenRepository tokenRepository,
    UserRepository userRepository,
    ApikeyRepository apikeyRepository,
    SessionRepository sessionRepository,
    ITokenService jwtService,
    IEmailService emailService,
    SessionService sessionService,
    SessionHelper sessionHelper,
    IHttpContextAccessor httpContextAccessor
) : IAuthService
{
    public async Task<AuthResponse> LogoutAsync(ClaimsPrincipal user)
    {
        var sessionIdClaim = user.FindFirst("SessionId")?.Value;
        if (string.IsNullOrEmpty(sessionIdClaim) || !int.TryParse(sessionIdClaim, out var sessionId))
            return new AuthResponse { Success = false, Message = "Invalid or missing SessionId claim." };

        var session = await sessionService.GetByIdAsync(sessionId);
        if (session == null || string.IsNullOrWhiteSpace(session.Jwt?.RefreshToken))
            return new AuthResponse { Success = false, Message = "No active session found." };

        await sessionService.EndAsync(session.Id);

        if (session.JwtId != null)
            await jwtService.RevokeToken(session.JwtId.Value);

        return new AuthResponse { Success = true, Message = "Logout successful." };
    }
    public async Task<AuthResponse> LoginAsync(LoginRequest request)
    {
        var user = await userRepository.GetByUserName(request.Username);

        if (user == null || !user.IsActive)
            return new AuthResponse { Success = false, Message = "Invalid credentials or user inactive." };

        if (!PasswordHasher.VerifyPassword(request.Password, user.EncPassword))
            return new AuthResponse { Success = false, Message = "Invalid credentials." };

        return await AuthenticateUserAsync(user);
    }
    public async Task<AuthResponse> GoogleLoginAsync(User user)
    {
        var existingUser = await userRepository.GetByEmail(user.Email);
        if (existingUser == null)
        {
            await userRepository.Add(user, null, "Google");
            return await AuthenticateUserAsync(user);
        }
        return await AuthenticateUserAsync(existingUser);
    }
    public async Task<AuthResponse> AuthenticateUserAsync(User user)
    {
        if (user == null || !user.IsActive)
            return new AuthResponse { Success = false, Message = "Invalid credentials or user inactive." };

        Session? existingSession = await FindSession(user);

        if (existingSession != null)
        {
            await sessionService.RefreshAsync(existingSession.Id);

            return new AuthResponse
            {
                Success = true,
                Message = "Session reused.",
                AccessToken = existingSession.Jwt.AccessToken,
                AccessTokenExpiration = existingSession.Jwt.AccessTokenExpiration,
                RefreshToken = existingSession.Jwt.RefreshToken,
                RefreshTokenExpiration = existingSession.Jwt.RefreshTokenExpiration,
                UserId = user.Id,
                Username = user.Username,
                Email = user.Email,
                SessionId = existingSession.Id
            };
        }

        var newSession = await sessionService.CreateAsync(sessionHelper.CreateNew(user));

        var refreshToken = jwtService.GenerateRefreshToken();
        var accessToken = jwtService.GenerateToken(user, newSession.Id);

        var newJwt = await tokenRepository.Add(refreshToken, user, accessToken);

        await sessionService.AttachJwtAsync(newSession.Id, newJwt);
        await sessionService.CacheSessionAsync(newSession);

        await emailService.GenerateLoginEmail(user, newJwt);

        return new AuthResponse
        {
            Success = true,
            Message = $"{user.Provider} login successful.",
            AccessToken = newJwt.AccessToken,
            AccessTokenExpiration = newJwt.AccessTokenExpiration,
            RefreshToken = newJwt.RefreshToken,
            RefreshTokenExpiration = newJwt.RefreshTokenExpiration,
            UserId = user.Id,
            Username = user.Username,
            Email = user.Email,
            SessionId = newSession.Id
        };
    }
    private async Task<Session?> FindSession(User user)
    {
        var httpContext = httpContextAccessor.HttpContext;
        var userAgent = httpContext?.Request.Headers["User-Agent"].ToString()?.Trim() ?? string.Empty;
        var os = UserAgentHelper.GetOSFromUserAgent(userAgent);
        var browser = UserAgentHelper.GetBrowserFromUserAgent(userAgent);
        var deviceInfo = $"{os}, {browser}".Trim().ToLowerInvariant();
        var ipAddress = httpContext?.Connection?.RemoteIpAddress?.ToString()?.Trim() ?? string.Empty;

        return await sessionService.FindActiveAsync(user.Id, deviceInfo, ipAddress);
    }
    public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
    {
        User existingUser = await userRepository.GetByEmailorMob(request);
        if (existingUser != null)
        {
            var emailExists = existingUser.Email == request.Email;
            var mobileExists = existingUser.MobileNumber == request.MobileNumber;

            return new AuthResponse
            {
                Success = false,
                Message = "Validation failed",
                Errors = new Dictionary<string, string[]>
            {
                { "Email", emailExists ? new[] { "Email already in use." } : Array.Empty<string>() },
                { "MobileNumber", mobileExists ? new[] { "Mobile number already in use." } : Array.Empty<string>() }
            }
            };
        }

        var hashedPassword = PasswordHasher.HashPassword(request.Password);
        User newUser = await userRepository.Add(new User
        {
            Username = request.Username,
            EncPassword = hashedPassword,
            Email = request.Email,
            Name = request.Name,
            MobileNumber = request.MobileNumber,
            IsActive = true,
            RoleId = request.RoleId,
            CreationDate = DateTime.Now,
            ResetPassToken = Guid.NewGuid().ToString(),
            ResetPassTokenExpiry = DateTime.Now.AddHours(1),
        }, hashedPassword, "Local");

        if (newUser == null)
            return new AuthResponse { Success = false, Message = "Failed to create user. Please try again later." };

        var newSession = await sessionService.CreateAsync(sessionHelper.CreateNew(newUser));

        var accessToken = jwtService.GenerateToken(newUser, newSession.Id);

        Jwt newJwt = await tokenRepository.Add(jwtService.GenerateRefreshToken(), newUser, accessToken);
        if (newJwt == null)
            return new AuthResponse { Success = false, Message = "Failed to create JWT. Please try again later." };

        await sessionService.AttachJwtAsync(newSession.Id, newJwt);
        await emailService.GenerateRegisterEmail(newUser, newJwt);

        return new AuthResponse
        {
            UserId = newUser.Id,
            Username = newUser.Username,
            Email = newUser.Email,
            Success = true,
            Message = "User registered successfully.",
            AccessToken = newJwt.AccessToken,
            AccessTokenExpiration = newJwt.AccessTokenExpiration,
            RefreshToken = newJwt.RefreshToken,
            RefreshTokenExpiration = newJwt.RefreshTokenExpiration,
            SessionId = newSession.Id
        };
    }
    public async Task<AuthResponse> ValidateApiKeyAsync(string apiKey)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            return new AuthResponse { Success = false, Message = "API key is required." };

        ApiKey apiKeyEntity = await apikeyRepository.GetValid(apiKey);

        if (apiKeyEntity == null)
            return new AuthResponse { Success = false, Message = "Invalid or expired API key." };

        return new AuthResponse
        {
            Success = true,
            Message = "API key is valid.",
            UserId = apiKeyEntity.UserId,
            Username = apiKeyEntity.UserName
        };
    }
}
