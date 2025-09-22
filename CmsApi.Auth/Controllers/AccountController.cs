using CmsApi.Auth.Models;
using CmsApi.Auth.Services;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using CmsApi.Auth.DTOs;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using CmsApi.Auth.Helpers;
using CmsApi.Auth.Repositories;

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

    //[HttpGet("google-response")]
    //public async Task<IActionResult> GoogleResponse()
    //{
    //    var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    //    var claims = result.Principal?.Identities?.FirstOrDefault()?.Claims;
    //    var email = claims?.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
    //    var name = claims?.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
    //    var givenName = claims?.FirstOrDefault(c => c.Type == "given_name")?.Value;
    //    var familyName = claims?.FirstOrDefault(c => c.Type == "family_name")?.Value;
    //    var phoneNumber = claims?.FirstOrDefault(c => c.Type == ClaimTypes.MobilePhone || c.Type == "phone_number")?.Value;
    //    foreach (var claim in User.Claims)
    //    {
    //        Console.WriteLine($"{claim.Type}: {claim.Value}");
    //    }

    //    if (string.IsNullOrEmpty(email))
    //        return Unauthorized(new AuthResponse { Success = false, Message = "Email claim missing from Google response." });

    //    var authResponse = await authService.GoogleLoginAsync(new User
    //    {
    //        Email = email,
    //        Username = email.Split('@')[0],
    //        Name = name,
    //        MobileNumber = phoneNumber,
    //        Provider = "Google",
    //        IsActive = true,
    //        CreationDate = DateTime.Now
    //    });

    //    if (authResponse == null || !authResponse.Success)
    //        return StatusCode(401, authResponse);

    //    return StatusCode(200, authResponse);
    //}


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

}
