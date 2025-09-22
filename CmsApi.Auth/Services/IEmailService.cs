using CmsApi.Auth.Models;

namespace CmsApi.Auth.Services;
public interface IEmailService
{
    Task SendAsync(string toEmail, string subject, string htmlBody);
    Task GenerateLoginEmail(User user, Jwt newJwt);
    Task GenerateRegisterEmail(User user, Jwt newJwt);
}

