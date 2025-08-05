using CmsApi.Auth.Data;
using CmsApi.Auth.DTOs;
using CmsApi.Auth.Helpers;
using CmsApi.Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace CmsApi.Auth.Services;

public class AuthService(AuthDbContext dbContext, IJwtService jwtService, IEmailService emailService) : IAuthService
{

    public async Task<bool> LogoutAsync(string token)
    {
        var jwtRecord = await dbContext.Jwts
            .FirstOrDefaultAsync(t => t.Token == token && !t.IsRevoked);

        if (jwtRecord == null)
            return false;

        jwtRecord.IsRevoked = true;
        await dbContext.SaveChangesAsync();
        return true;
    }
    public async Task<AuthResponse> LoginAsync(LoginRequest request)
    {
        var user = await dbContext.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Username == request.Username);

        if (user == null || !user.IsActive)
            return new AuthResponse { Success = false, Message = "Invalid credentials or user inactive." };

        // Verify password
        if (!PasswordHasher.VerifyPassword(request.Password, user.EncPassword))
            return new AuthResponse { Success = false, Message = "Invalid credentials." };

        var token = jwtService.GenerateToken(user);

        // Send login notification email
        var htmlBody = $@"
        <h3>Hello {user.Name},</h3>
        <p>You have just logged in to your account.</p>
        <p>Here is your JWT token:</p>
        <p><code>{token}</code></p>
        <p>If this wasn't you, please reset your password immediately.</p>
    ";

        await emailService.SendAsync(user.Email, "Login Notification", htmlBody);

        return new AuthResponse
        {
            Success = true,
            Token = token,
            UserId = user.Id,
            Username = user.Username
        };
    }
    public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
    {
        var existingUser = await dbContext.Users
            .FirstOrDefaultAsync(u => u.Username == request.Username);

        if (existingUser != null)
        {
            return new AuthResponse
            {
                Success = false,
                Message = "Username already exists."
            };
        }

        // Hash authResponsesh the password
        var hashedPassword = PasswordHasher.HashPassword(request.Password);

        var newUser = new User
        {
            Username = request.Username,
            Password = request.Password,
            EncPassword = hashedPassword,
            Email = request.Email,
            Name = request.Name,
            MobileNumber = request.MobileNumber,
            IsActive = true,
            CreationDate = DateTime.UtcNow,
            RoleId = request.RoleId
        };

        dbContext.Users.Add(newUser);
        await dbContext.SaveChangesAsync();

        var token = jwtService.GenerateToken(newUser);

        //Send welcome email with token
        var htmlBody = $@"
        <h3>Welcome {newUser.Name}!</h3>
        <p>Thank you for registering. Here's your login token:</p>
        <p><code>{token}</code></p>
        <p>Use this token to access your account. Keep it secure.</p>
    ";

        await emailService.SendAsync(newUser.Email, "Welcome to Our System 🎉", htmlBody);

        return new AuthResponse
        {
            Success = true,
            Message = "User registered successfully.",
            Token = token
        };
    }
    public async Task<AuthResponse> ValidateTokenAsync(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return new AuthResponse
            {
                Success = false,
                Message = "Token is missing."
            };
        }

        var principal = jwtService.ValidateToken(token);
        if (principal == null)
        {
            return new AuthResponse
            {
                Success = false,
                Message = "Invalid or expired token."
            };
        }

        var username = principal.Identity?.Name;

        if (string.IsNullOrEmpty(username))
        {
            return new AuthResponse
            {
                Success = false,
                Message = "Invalid token payload."
            };
        }

        var user = await dbContext.Users
            .FirstOrDefaultAsync(u => u.Username == username && u.IsActive);

        if (user == null)
        {
            return new AuthResponse
            {
                Success = false,
                Message = "User not found or inactive."
            };
        }

        return new AuthResponse
        {
            Success = true,
            Message = "Token is valid.",
            Token = token,
            UserId = user.Id,
            Username = user.Username
        };
    }
    public async Task<AuthResponse> ValidateApiKeyAsync(string apiKey)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return new AuthResponse
            {
                Success = false,
                Message = "API key is required."
            };
        }

        var apiKeyEntity = await dbContext.ApiKeys
            .FirstOrDefaultAsync(k =>
                k.Key == apiKey &&
                k.IsActive &&
                (k.ExpiresAt == null || k.ExpiresAt > DateTime.UtcNow));

        if (apiKeyEntity == null)
        {
            return new AuthResponse
            {
                Success = false,
                Message = "Invalid or expired API key."
            };
        }

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
        var user = await dbContext.Users
            .FirstOrDefaultAsync(u => u.Email == request.EmailOrUsername || u.Username == request.EmailOrUsername);

        if (user == null) return false;

        var token = Guid.NewGuid().ToString();
        user.ResetToken = token;
        user.ResetTokenExpiry = DateTime.UtcNow.AddHours(1);

        await dbContext.SaveChangesAsync();

        var resetLink = $"https://localhost:44306/reset-password?token={token}";

        await emailService.SendAsync(user.Email, "Password Reset", $"Use this link to reset your password: {resetLink}");

        return true;
    }
    public async Task<bool> ResetPasswordAsync(ResetPasswordRequest request)
    {
        var user = await dbContext.Users
            .FirstOrDefaultAsync(u => u.ResetToken == request.Token && u.ResetTokenExpiry > DateTime.UtcNow);

        if (user == null) return false;

        user.Password = PasswordHasher.HashPassword(request.NewPassword);
        user.ResetToken = null;
        user.ResetTokenExpiry = null;

        await dbContext.SaveChangesAsync();
        return true;
    }


}
