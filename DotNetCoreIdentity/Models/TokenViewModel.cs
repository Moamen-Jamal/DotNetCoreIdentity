using System;

namespace DotNetCoreIdentity.Models
{
    public class TokenViewModel
    {
        public string Token { get; set; } = string.Empty;
        public DateTime ExpiresUtc { get; set; }
    }
}


