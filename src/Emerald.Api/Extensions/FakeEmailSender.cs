using Emerald.Api.Interfaces;

namespace Emerald.Api.Extensions;

public class FakeEmailSender : IEmailSender
{
    private readonly ILogger<FakeEmailSender> _logger;

    public FakeEmailSender(ILogger<FakeEmailSender> logger)
    {
        _logger = logger;
    }

    public async Task<bool> SendEmailAsync(string emailTo, string subject, string confirmationLink)
    {
        await Task.Run(() =>
            _logger.LogInformation("Fake email service executed SendEmailAsync. Details: EmailTo: {EmailTo}, Subject: {Subject}, ConfirmationLink: {ConfirmationLink}",
                emailTo, subject, confirmationLink));

        return true;
    }
}

