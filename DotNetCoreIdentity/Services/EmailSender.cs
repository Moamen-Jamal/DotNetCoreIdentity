using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace DotNetCoreIdentity.Services
{
    public class EmailSender : IEmailSender
    {
        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            // Demo: In real app, integrate SMTP or a provider like SendGrid.
            System.Console.WriteLine($"EMAIL to {email}: {subject} -> {htmlMessage}");
            return Task.CompletedTask;
        }
    }
}


