using CmsApi.Auth.DTOs;
using CmsApi.Auth.Models;
using CmsApi.Auth.Services;
using Microsoft.AspNetCore.Mvc;

namespace CmsApi.Auth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(IAuthService authService, IJwtService tokenService) : ControllerBase
{
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var authResponse = await authService.LoginAsync(request);
        if (authResponse == null || authResponse.Success == false)
            return Unauthorized("Invalid credentials");

        return Ok(authResponse);
    }
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState
                .Where(e => e.Value.Errors.Count > 0)
                .ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
                );

            return BadRequest(new { Message = "Validation failed", Errors = errors });
        }

        var result = await authService.RegisterAsync(request);
        if (!result.Success)
            return BadRequest(result);

        return Ok(result);
    }
    [HttpPost("validate-token")]
    public async Task<IActionResult> ValidateToken([FromBody] string token)
    {
        var result = await authService.ValidateTokenAsync(token);
        return result.Success ? Ok(result) : Unauthorized(result);
    }
    [HttpPost("validate-apikey")]
    public async Task<IActionResult> ValidateApiKey([FromBody] string apiKey)
    {
        var result = await authService.ValidateApiKeyAsync(apiKey);
        return result.Success ? Ok(result) : Unauthorized(result);
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return BadRequest("Refresh token is required.");

        var result = await authService.RefreshTokenAsync(token);

        if (!result.Success)
            return Unauthorized(result.Message);

        return Ok(result);
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        var success = await authService.ForgotPasswordAsync(request);
        return success ? Ok("Reset email sent") : NotFound("User not found");
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        var success = await authService.ResetPasswordAsync(request);
        return success ? Ok("Password reset successful") : BadRequest("Invalid or expired token");
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] string token)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var authResponse = await authService.LogoutAsync(token);
        if (authResponse == false)
            return Unauthorized("Can't logout");

        return Ok(authResponse);
    }
}
