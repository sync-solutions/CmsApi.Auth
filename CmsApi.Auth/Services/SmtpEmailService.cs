using System.Net.Mail;
using System.Net;
using CmsApi.Auth.Models;

namespace CmsApi.Auth.Services;

public class SmtpEmailService(IConfiguration config) : IEmailService
{
    private readonly IConfiguration _config = config;

    public async Task GenerateLoginEmail(User user, Jwt newJwt)
    {
        var htmlBody = $@"
        <h3>Hello {user.Name},</h3>
        <p>You have just logged in to your account.</p>
        <p>Here is your JWT token:</p>
        <p><code>{newJwt.AccessToken}</code></p>
        <p>And your Refresh token:</p>
        <p><code>{newJwt.RefreshToken}</code></p>
        <p>If this wasn't you, please reset your password immediately.</p>
    ";
        await SendAsync(user.Email, "Login Notification", htmlBody);
    }
    public async Task GenerateRegisterEmail(User user, Jwt newJwt)
    {
        var htmlBody = $@"
        <h3>Welcome {user.Name}!</h3>
        <p>Thank you for registering. Here's your login token:</p>
        <p><code>{newJwt.AccessToken}</code></p>
        <p>And your Refresh token:</p>
        <p><code>{newJwt.RefreshToken}</code></p>
        <p>Use those tokens to access your account. Keep it secure.</p>
    ";
        await SendAsync(user.Email, "Welcome to Our System 🎉", htmlBody);
    }
    public async Task SendAsync(string toEmail, string subject, string htmlBody)
    {
        var smtpClient = new SmtpClient(_config["Smtp:Host"])
        {
            Port = int.Parse(_config["Smtp:Port"]),
            Credentials = new NetworkCredential(
                _config["Smtp:Username"],
                _config["Smtp:Password"]
            ),
            EnableSsl = true,
        };

        var mailMessage = new MailMessage
        {
            From = new MailAddress(_config["Smtp:From"]),
            Subject = subject,
            Body = htmlBody,
            IsBodyHtml = true,
        };

        mailMessage.To.Add(toEmail);

        await smtpClient.SendMailAsync(mailMessage);
    }
}
