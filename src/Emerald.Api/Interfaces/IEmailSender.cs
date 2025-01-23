
namespace Emerald.Api.Interfaces;

public interface IEmailSender
{
    Task<bool> SendEmailAsync(string emailTo, string subject, string confirmationLink);
}