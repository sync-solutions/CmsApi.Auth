namespace CmsApi.Auth.Services;
public interface IEmailService
{
    Task SendAsync(string toEmail, string subject, string htmlBody);
}

