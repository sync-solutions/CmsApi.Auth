using CmsApi.Auth.DTOs;
using CmsApi.Auth.Helpers;
using CmsApi.Auth.Models;
using CmsApi.Auth.Repositories;
using CmsApi.Auth.Services;
using Microsoft.AspNetCore.Mvc;
using ForgotPasswordRequest = CmsApi.Auth.DTOs.ForgotPasswordRequest;
using ResetPasswordRequest = CmsApi.Auth.DTOs.ResetPasswordRequest;

namespace CmsApi.Auth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(IAuthService authService, ITokenService tokenService, SessionService sessionService,
                            UserRepository userRepository, PasswordService passwordService) : ControllerBase
{
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

        var result = await tokenService.GetTokenValidationResponse(token);
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

        var result = await tokenService.RefreshTokenAsync(token);
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

        var success = await passwordService.ForgotPasswordAsync(request);
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

        var success = await passwordService.ResetPasswordAsync(request);
        return success
            ? Ok(new AuthResponse { Success = true, Message = "Password reset successful." })
            : BadRequest(new AuthResponse { Success = false, Message = "Invalid or expired token." });
    }
    [HttpPost("set-password")]
    public async Task<IActionResult> SetPassword([FromBody] SetPasswordRequest request)
    {
        var user = await userRepository.GetByEmail(request.Email);

        if (user == null || !user.IsActive || !string.IsNullOrEmpty(user.EncPassword))
            return BadRequest("Invalid request or password already set.");

        await userRepository.SetPassword(user.Id, PasswordHasher.HashPassword(request.NewPassword));

        return Ok("Password set successfully.");
    }

    [HttpPost("revoke-session")]
    public async Task<IActionResult> RevokeSession([FromBody] int sessionId)
    {
        if (!await sessionService.EndAsync(sessionId))
            return BadRequest("Session Doesn't Exist or Already Expired");

        return Ok("Session Revoked successfully.");
    }


}

