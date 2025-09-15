using CmsApi.Auth.DTOs;
using CmsApi.Auth.Models;
using CmsApi.Auth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
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
        {
            var errors = ModelState
                .Where(e => e.Value.Errors.Count > 0)
                .ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
                );

            return BadRequest(new AuthResponse { Success = false, Message = "Validation failed", Errors = errors });
        }

        var authResponse = await authService.LoginAsync(request);
        if (authResponse == null || !authResponse.Success)
            return StatusCode(401, authResponse);

        return StatusCode(200, authResponse);
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

            return BadRequest(new AuthResponse { Success = false, Message = "Validation failed", Errors = errors });
        }

        var result = await authService.RegisterAsync(request);
        if (!result.Success)
            return BadRequest(result);

        return Ok(result);
    }

    [HttpPost("validate-token")]
    public async Task<IActionResult> ValidateToken([FromBody] string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return BadRequest(new AuthResponse
            {
                Success = false,
                Message = "Token is missing",
                StatusCode = StatusCodes.Status400BadRequest
            });

        var result = await authService.ValidateTokenAsync(token);
        return result.Success
            ? Ok(result)
            : StatusCode(StatusCodes.Status401Unauthorized, result);
    }


    [HttpPost("validate-apikey")]
    public async Task<IActionResult> ValidateApiKey([FromBody] string apiKey)
    {
        var result = await authService.ValidateApiKeyAsync(apiKey);
        return result.Success ? Ok(result) : StatusCode(401, result);
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return BadRequest(new AuthResponse
            {
                Success = false,
                Message = "Refresh token is required."
            });
        }

        var result = await authService.RefreshTokenAsync(token);
        if (!result.Success)
        {
            return StatusCode(401, new AuthResponse
            {
                Success = false,
                Message = result.Message ?? "Invalid or expired refresh token."
            });
        }

        return Ok(result);
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState
                .Where(e => e.Value.Errors.Count > 0)
                .ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
                );

            return BadRequest(new AuthResponse { Success = false, Message = "Validation failed", Errors = errors });
        }

        var success = await authService.ForgotPasswordAsync(request);
        return success
            ? Ok(new AuthResponse { Success = true, Message = "Reset email sent." })
            : NotFound(new AuthResponse { Success = false, Message = "User not found." });
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState
                .Where(e => e.Value.Errors.Count > 0)
                .ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
                );

            return BadRequest(new AuthResponse { Success = false, Message = "Validation failed", Errors = errors });
        }

        var success = await authService.ResetPasswordAsync(request);
        return success
            ? Ok(new AuthResponse { Success = true, Message = "Password reset successful." })
            : BadRequest(new AuthResponse { Success = false, Message = "Invalid or expired token." });
    }

    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var authResponse = await authService.LogoutAsync(User);
        if (authResponse == null || !authResponse.Success)
            return StatusCode(401, authResponse);

        return Ok(authResponse);
    }

}

