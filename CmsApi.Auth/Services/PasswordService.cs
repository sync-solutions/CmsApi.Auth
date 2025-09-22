using CmsApi.Auth.DTOs;
using CmsApi.Auth.Helpers;
using CmsApi.Auth.Models;
using CmsApi.Auth.Repositories;

namespace CmsApi.Auth.Services;

public class PasswordService(UserRepository userRepository, SessionService sessionService, IEmailService emailService)
{
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
    public async Task<bool> ForgotPasswordAsync(ForgotPasswordRequest request)
    {
        var user = await userRepository.GetByEmailorUserName(request.EmailOrUsername);
        if (user == null) return false;

        string token = await userRepository.UpdateResetPassToken(user);

        var resetLink = $"https://localhost:44306/reset-password?token={token}";
        await emailService.SendAsync(user.Email, "Password Reset", $"Use this link to reset your password: {resetLink}");

        return true;
    }
}
