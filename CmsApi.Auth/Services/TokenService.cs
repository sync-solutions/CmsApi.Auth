using CmsApi.Auth.Models;
using CmsApi.Auth.Repositories;
using CmsApi.Auth.Services;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace CmsApi.Auth.Services;
public class TokenService(IOptions<JwtSettings> opts, TokenRepository tokenRepository, SessionService sessionService,
                          UserRepository userRepository, SessionRepository sessionRepository) : ITokenService
{
    private readonly JwtSettings _settings = opts.Value;

    public string GenerateToken(User user, int sessionId)
    {
        var claims = new[]
        {
      new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
      new Claim("SessionId", sessionId.ToString()),
      new Claim("RoleId", user.RoleId.ToString()),
      new Claim(ClaimTypes.Name, user.Username!)
    };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.Key));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expires = DateTime.Now.AddMinutes(_settings.AccessTokenExpiryMins);

        var token = new JwtSecurityToken(
          //issuer: _settings.Issuer,
          //audience: _settings.Issuer,
          claims: claims,
          expires: expires,
          signingCredentials: creds
        );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    public async Task<bool> RevokeToken(int tokenId)
    {
        return await tokenRepository.RevokeToken(tokenId);
    }
    public string GenerateRefreshToken()
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }
    public async Task<AuthResponse> RefreshTokenAsync(string refreshToken)
    {
        var jwt = await tokenRepository.GetByRefreshToken(refreshToken);
        if (jwt == null || jwt.RefreshTokenExpiration < DateTime.Now)
            return new AuthResponse { Success = false, Message = "Invalid or expired refresh token." };

        var user = await userRepository.GetById(jwt.UserId);
        if (user == null)
            return new AuthResponse { Success = false, Message = "User not found." };

        var session = await sessionRepository.GetByJwtIdAsync(jwt.Id);
        var sessionId = session?.Id;
        if (sessionId.HasValue)
        {
            await sessionService.RefreshAsync(sessionId.Value);

            var newAccessToken = GenerateToken(user, sessionId.Value);
            var newRefreshToken = GenerateRefreshToken();

            jwt.AccessToken = newAccessToken;
            jwt.RefreshToken = newRefreshToken;
            jwt.AccessTokenExpiration = DateTime.Now.AddMinutes(15);
            jwt.RefreshTokenExpiration = DateTime.Now.AddDays(7);

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
        else
        {
            return new AuthResponse
            {
                Success = false,
                Message = "Session not found for token.",
                UserId = user.Id,
                Email = user.Email,
                Username = user.Username
            };
        }
    }
    public async Task<bool> IsRefreshTokenValidAsync(string refreshToken)
    {
        var jwt = await tokenRepository.GetByRefreshToken(refreshToken);
        return jwt != null && jwt.RefreshTokenExpiration > DateTime.Now;
    }
    public ClaimsPrincipal? ValidateToken(string token)
    {
        var key = Encoding.UTF8.GetBytes(_settings.Key);
        try
        {
            var principal = new JwtSecurityTokenHandler()
              .ValidateToken(token, new TokenValidationParameters
              {
                  ValidateIssuer = false,
                  //ValidIssuer = _settings.Issuer,
                  ValidateAudience = false,
                  //ValidAudiences = [_settings.Audience, _settings.Issuer],
                  ValidateIssuerSigningKey = true,
                  IssuerSigningKey = new SymmetricSecurityKey(key),
                  ValidateLifetime = true
              }, out _);
            return principal;
        }
        catch
        {
            return null;
        }
    }
    public async Task<AuthResponse> GetTokenValidationResponse(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return new AuthResponse { Success = false, Message = "Token is missing." };

        var jwt = await tokenRepository.Get(token);
        if (jwt == null || jwt.RefreshTokenExpiration < DateTime.Now)
            return new AuthResponse { Success = false, Message = "Invalid or expired token." };

        var principal = ValidateToken(token);
        if (principal == null)
            return new AuthResponse { Success = false, Message = "Invalid or expired token." };

        var usernameClaim = principal.Identity?.Name;
        var UserIdClaim = int.TryParse(principal.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var uid) ? uid : 0;
        var RoleIdClaim = int.TryParse(principal.FindFirst(ClaimTypes.Role)?.Value, out var rid) ? rid : 0;

        if (string.IsNullOrEmpty(usernameClaim) || UserIdClaim == 0 || RoleIdClaim == 0)
            return new AuthResponse { Success = false, Message = "Invalid token payload." };

        return new AuthResponse
        {
            Success = true,
            Message = "Token is valid.",
            AccessToken = token,
            UserId = UserIdClaim,
            Username = usernameClaim,
            RoleId = RoleIdClaim
        };
    }
}
