using System.Net;
using System.Net.Mail;
using Emerald.Api.Interfaces;

namespace Emerald.Api.Extensions;

public class EmailSender : IEmailSender
{
    private readonly IConfiguration _configuration;

    public EmailSender(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    public async Task<bool> SendEmailAsync(string emailTo, string subject, string confirmationLink)
    {
        var emailFrom = _configuration.GetValue<string>("EmailConfiguration:Email");
        var password = _configuration.GetValue<string>("EmailConfiguration:Password");
        var host = _configuration.GetValue<string>("EmailConfiguration:Host");
        var port = _configuration.GetValue<int>("EmailConfiguration:Port");

        var body = $@"
                    <!DOCTYPE html>
                    <html lang=""en"">
                    <head>
                        <meta charset=""UTF-8"">
                        <title>Confirm Your Email Address</title>
                    </head>
                    <body>
                        <div style=""max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif;"">
                            <h2>Confirm Your Email Address</h2>
                            <p>Hi,</p>
                            <p>
                                Please confirm your email address by clicking the button below:
                            </p>
                            <br><br>
                            <a href=""{confirmationLink}"" style=""display: inline-block; padding: 10px 20px; color: #ffffff; background-color: #009A44; text-decoration: none; border-radius: 5px;"">
                                Confirm Email
                            </a>
                            <br><br><br>
                            <p>
                                If you didn't request this email, you can safely ignore it.
                            </p>
                            <p>Thank you!</p>
                        </div>
                    </body>
                    </html>";

        try
        {
            var smtp = new SmtpClient(host, port);
            smtp.EnableSsl = true;
            smtp.UseDefaultCredentials = false;
            smtp.Credentials = new NetworkCredential(emailFrom, password);

            var mailMessage = new MailMessage
            {
                From = new MailAddress(emailFrom!, "Emerald API"),
                Subject = subject,
                Body = body,
                IsBodyHtml = true,
            };

            mailMessage.To.Add(emailTo);

            await smtp.SendMailAsync(mailMessage);
        }
        catch
        {
            return false;
        }

        return true;
    }
}
