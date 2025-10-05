using CmsApi.Auth.DTOs;
using CmsApi.Auth.Helpers;
using CmsApi.Auth.Models;
using CmsApi.Auth.Repositories;
using CmsApi.Auth.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CmsApi.Auth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AccountController(IAuthService authService, ITokenService tokenService, UserRepository userRepository,
                               SessionService sessionService, SessionHelper sessionHelper) : ControllerBase
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

    [HttpGet("google-login")]
    public IActionResult GoogleLogin()
    {
        var props = new AuthenticationProperties
        {
            RedirectUri = "/api/account/post-login"
        };
        return Challenge(props, GoogleDefaults.AuthenticationScheme);
    }
    [HttpGet("post-login")]
    public async Task<IActionResult> PostLogin()
    {
        var email = User.FindFirst("email")?.Value;
        var name = User.FindFirst("name")?.Value;

        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(name))
            return Unauthorized(new AuthResponse { Success = false, Message = "some claims are missing from Google response." });

        var authResponse = await authService.GoogleLoginAsync(new User
        {
            Email = email,
            Username = email.Split('@')[0],
            Name = name,
            Provider = "Google",
            IsActive = true,
            CreationDate = DateTime.Now,
            RoleId = 6 // Default role ID for Google users
        });

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

    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var authResponse = await authService.LogoutAsync(User);
        if (authResponse == null || !authResponse.Success)
            return StatusCode(401, authResponse);

        return Ok(authResponse);
    }

    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [HttpPost("edit")]
    public async Task<IActionResult> Edit([FromBody] UserEditRequest userEditRequest)
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
        if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int userId))
        {
            return Unauthorized(new AuthResponse { Success = false, Message = "Invalid user ID in token." });
        }

        var authResponse = await userRepository.Update(userId, userEditRequest);
        if (authResponse?.Success == false)
        {
            return NotFound(authResponse);
        }

        return Ok(authResponse);
    }
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [HttpPost("delete")]
    public async Task<IActionResult> Delete([FromBody] int id)
    {
        if (id == null)
        {
            return BadRequest(new AuthResponse { Success = false, Message = "User ID ain't Provided." });
        }

        var deleted = await userRepository.DeleteAsync(id);
        if (!deleted)
        {
            return NotFound(new AuthResponse { Success = false, Message = "Invalid user ID." });
        }

        return Ok(new AuthResponse { Success = true, Message = "User Deleted Successfully" });
    }
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [HttpPost("delete-many")]
    public async Task<IActionResult> DeleteMany([FromBody] int[] ids)
    {
        if (ids == null || ids.Length == 0)
        {
            return BadRequest(new AuthResponse { Success = false, Message = "Users IDs ain't Provided." });
        }

        var deleted = await userRepository.DeleteManyAsync(ids);
        if (!deleted)
        {
            return NotFound(new AuthResponse { Success = false, Message = "Invalid Users IDs." });
        }

        return Ok(new AuthResponse { Success = true, Message = "Users Deleted Successfully" });
    }
}
