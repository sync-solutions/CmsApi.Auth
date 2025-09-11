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
    IJwtService jwtService,
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

        return new AuthResponse { Success = true, Message = "Logout successful." };
    }
    public async Task<AuthResponse> LoginAsync(LoginRequest request)
    {
        var user = await userRepository.GetByUserName(request.Username);

        if (user == null || !user.IsActive)
            return new AuthResponse { Success = false, Message = "Invalid credentials or user inactive." };

        if (!PasswordHasher.VerifyPassword(request.Password, user.EncPassword))
            return new AuthResponse { Success = false, Message = "Invalid credentials." };

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

        var newSession = await sessionService.CreateAsync(
            sessionHelper.CreateNew(user, null) // null JWT for now
        );

        var refreshToken = jwtService.GenerateRefreshToken();
        var accessToken = jwtService.GenerateToken(user, newSession.Id);

        var newJwt = await tokenRepository.Add(refreshToken, user, accessToken);

        await sessionService.AttachJwtAsync(newSession.Id, newJwt);

        await SendLoginEmail(user, newJwt);

        return new AuthResponse
        {
            Success = true,
            Message = "Login successful.",
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
    private async Task SendLoginEmail(User user, Jwt newJwt)
    {
        var htmlBody = $@"
        <h3>Hello {user.Name},</h3>
        <p>You have just logged in to your account.</p>
        <p>Here is your JWT token:</p>
        <p><code>{newJwt.AccessToken}</code></p>
        <p>And your Refresh token:</p>
        <p><code>{newJwt.RefreshToken}</code></p>
        <p>If this wasn't you, please reset your password immediately.</p>
    ";
        await emailService.SendAsync(user.Email, "Login Notification", htmlBody);
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
        var refreshToken = jwtService.GenerateRefreshToken();
        User newUser = await userRepository.Add(request, hashedPassword, refreshToken);

        if (newUser == null)
            return new AuthResponse { Success = false, Message = "Failed to create user. Please try again later." };

        var newSession = await sessionService.CreateAsync(sessionHelper.CreateNew(newUser, null));

        var accessToken = jwtService.GenerateToken(newUser, newSession.Id);

        Jwt newJwt = await tokenRepository.Add(refreshToken, newUser, accessToken);
        if (newJwt == null)
            return new AuthResponse { Success = false, Message = "Failed to create JWT. Please try again later." };

        await sessionService.AttachJwtAsync(newSession.Id, newJwt);

        var htmlBody = $@"
        <h3>Welcome {newUser.Name}!</h3>
        <p>Thank you for registering. Here's your login token:</p>
        <p><code>{newJwt.AccessToken}</code></p>
        <p>And your Refresh token:</p>
        <p><code>{newJwt.RefreshToken}</code></p>
        <p>Use those tokens to access your account. Keep it secure.</p>
    ";
        await emailService.SendAsync(newUser.Email, "Welcome to Our System 🎉", htmlBody);

        // 8️⃣ Return response
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
    public async Task<AuthResponse> ValidateTokenAsync(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return new AuthResponse { Success = false, Message = "Token is missing." };

        var jwt = await tokenRepository.Get(token);
        if (jwt == null || jwt.RefreshTokenExpiration < DateTime.UtcNow)
            return new AuthResponse { Success = false, Message = "Invalid or expired token." };

        var principal = jwtService.ValidateToken(token);
        if (principal == null)
            return new AuthResponse { Success = false, Message = "Invalid or expired token." };

        var username = principal.Identity?.Name;
        if (string.IsNullOrEmpty(username))
            return new AuthResponse { Success = false, Message = "Invalid token payload." };

        var user = await userRepository.GetByUserName(username);
        if (user == null)
            return new AuthResponse { Success = false, Message = "User not found or inactive." };

        var sessionId = sessionRepository.GetByJwtIdAsync(jwt.Id).Result?.Id;

        if (sessionId.HasValue)
            await sessionService.RefreshAsync(sessionId.Value);

        return new AuthResponse
        {
            Success = true,
            Message = "Token is valid.",
            AccessToken = token,
            UserId = user.Id,
            Username = user.Username
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
    public async Task<bool> ForgotPasswordAsync(ForgotPasswordRequest request)
    {
        var user = await userRepository.GetByEmailorUserName(request.EmailOrUsername);
        if (user == null) return false;

        string token = await userRepository.GenerateResetPassToken(user);

        var resetLink = $"https://localhost:44306/reset-password?token={token}";
        await emailService.SendAsync(user.Email, "Password Reset", $"Use this link to reset your password: {resetLink}");

        return true;
    }
    public async Task<bool> ResetPasswordAsync(ResetPasswordRequest request)
    {
        User user = await userRepository.GetByValidResetToken(request);
        if (user == null) return false;

        user.EncPassword = PasswordHasher.HashPassword(request.NewPassword);
        user.ResetPassToken = null;
        user.ResetPassTokenExpiry = null;

        await userRepository.Update(user);

        await sessionService.EndAsync(user.Id);

        return true;
    }
    public async Task<AuthResponse> RefreshTokenAsync(string refreshToken)
    {
        var jwt = await tokenRepository.GetByRefreshToken(refreshToken);
        if (jwt == null || jwt.RefreshTokenExpiration < DateTime.UtcNow)
            return new AuthResponse { Success = false, Message = "Invalid or expired refresh token." };

        var user = await userRepository.GetById(jwt.UserId);
        if (user == null)
            return new AuthResponse { Success = false, Message = "User not found." };

        var sessionId = sessionRepository.GetByJwtIdAsync(jwt.Id).Result?.Id;


        if (sessionId.HasValue)
            await sessionService.RefreshAsync(sessionId.Value);

        var newAccessToken = jwtService.GenerateToken(user, sessionId.Value);
        var newRefreshToken = jwtService.GenerateRefreshToken();

        jwt.AccessToken = newAccessToken;
        jwt.RefreshToken = newRefreshToken;
        jwt.AccessTokenExpiration = DateTime.UtcNow.AddMinutes(15);
        jwt.RefreshTokenExpiration = DateTime.UtcNow.AddDays(7);

        await tokenRepository.Update(jwt);

        return new AuthResponse
        {
            Success = true,
            Email = user.Email,
            AccessToken = newAccessToken,
            AccessTokenExpiration = jwt.AccessTokenExpiration,
            RefreshToken = newRefreshToken,
            RefreshTokenExpiration = jwt.RefreshTokenExpiration,
            UserId = user.Id,
            Username = user.Username,
            SessionId = sessionId,
            Message = "Access token refreshed."
        };
    }
}
