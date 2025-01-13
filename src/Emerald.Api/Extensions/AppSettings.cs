namespace Emerald.Api.Extensions
{
    public class AppSettings
    {
        public string Secret { get; set; } = string.Empty;
        public int ExpirationInMinutes { get; set; }
        public string Issuer { get; set; } = string.Empty;
        public string Audience { get; set; } = string.Empty;
    }
}
