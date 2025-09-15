using CmsApi.Auth.Models;
using CmsApi.Auth.Repositories;
using CmsApi.Auth.Services;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

public class JwtService(IOptions<JwtSettings> opts, TokenRepository tokenRepository) : IJwtService
{
    private readonly JwtSettings _settings = opts.Value;

    public string GenerateToken(User user, int sessionId)
    {
        var claims = new[]
        {
      new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
      new Claim("SessionId", sessionId.ToString()),
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
}
