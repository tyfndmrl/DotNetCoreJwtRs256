using System;
using System.Collections.Generic;
using System.Text;

namespace JsonWebToken.Core.Authentication.Models
{
    public class JwtTokenSettings
    {
        public bool ValidateIssuerSigningKey { get; set; }
        public bool ValidateLifetime { get; set; }
        public bool ValidateIssuer { get; set; }
        public string ValidIssuer { get; set; }
        public bool ValidateAudience { get; set; }
        public string ValidAudience { get; set; }
        public int ClockSkew { get; set; }
        public int Expires { get; set; }
    }
}
