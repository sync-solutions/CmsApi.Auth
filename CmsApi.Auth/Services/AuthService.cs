using CmsApi.Auth.DTOs;
using CmsApi.Auth.Helpers;
using CmsApi.Auth.Models;
using CmsApi.Auth.Repositories;

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
    public async Task<bool> LogoutAsync(string token)
    {
        Jwt jwtRecord = await tokenRepository.Get(token);

        if (jwtRecord == null)
            return false;

        jwtRecord = await tokenRepository.RevokeToken(jwtRecord);

        await sessionService.EndSessionAsync(jwtRecord.UserId);

        return true;
    }

    public async Task<AuthResponse> LoginAsync(LoginRequest request)
    {
        var user = await userRepository.GetByUserName(request.Username);

        if (user == null || !user.IsActive)
            return new AuthResponse { Success = false, Message = "Invalid credentials or user inactive." };

        if (!PasswordHasher.VerifyPassword(request.Password, user.EncPassword))
            return new AuthResponse { Success = false, Message = "Invalid credentials." };

        var newJwt = await tokenRepository.Add(
        jwtService.GenerateRefreshToken(),
        user,
        jwtService.GenerateToken(user)
    );
        Session session = sessionHelper.CreateNew(user, newJwt);

        await sessionService.CreateSessionAsync(session);

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

        return new AuthResponse
        {
            Success = true,
            AccessToken = newJwt.AccessToken,
            AccessTokenExpiration = newJwt.AccessTokenExpiration,
            RefreshToken = newJwt.RefreshToken,
            RefreshTokenExpiration = newJwt.RefreshTokenExpiration,
            UserId = user.Id,
            Username = user.Username
        };
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
                Message = emailExists && mobileExists
                    ? "Email and mobile number are already in use."
                    : emailExists ? "Email is already in use." : "Mobile number is already in use."
            };
        }

        var hashedPassword = PasswordHasher.HashPassword(request.Password);

        var refreshToken = jwtService.GenerateRefreshToken();
        User newUser = await userRepository.Add(request, hashedPassword, refreshToken);
        Jwt newJwt = await tokenRepository.Add(refreshToken, newUser, jwtService.GenerateToken(newUser));

        if (newUser == null || newJwt == null)
        {
            return new AuthResponse { Success = false, Message = "Failed to create user. Please try again later." };
        }

        Session session = sessionHelper.CreateNew(newUser, newJwt);

        await sessionService.CreateSessionAsync(session);

        var htmlBody = $@"
        <h3>Welcome {newUser.Name}!</h3>
        <p>Thank you for registering. Here's your login token:</p>
        <p><code>{newJwt.AccessToken}</code></p>
        <p>And your Refresh token:</p>
        <p><code>{newJwt.RefreshToken}</code></p>
        <p>Use those tokens to access your account. Keep it secure.</p>
    ";

        await emailService.SendAsync(newUser.Email, "Welcome to Our System 🎉", htmlBody);

        return new AuthResponse
        {
            UserId = newUser.Id,
            Success = true,
            Message = "User registered successfully.",
            AccessToken = newJwt.AccessToken,
            AccessTokenExpiration = newJwt.AccessTokenExpiration,
            RefreshToken = newJwt.RefreshToken,
            RefreshTokenExpiration = newJwt.RefreshTokenExpiration
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
            await sessionService.RefreshSessionAsync(sessionId.Value);

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

        user.Password = request.NewPassword;
        user.EncPassword = PasswordHasher.HashPassword(request.NewPassword);
        user.ResetPassToken = null;
        user.ResetPassTokenExpiry = null;

        await userRepository.Update(user);

        await sessionService.EndSessionAsync(user.Id);

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

        // Refresh the same session if present
        if (sessionId.HasValue)
            await sessionService.RefreshSessionAsync(sessionId.Value);

        var newAccessToken = jwtService.GenerateToken(user);
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
