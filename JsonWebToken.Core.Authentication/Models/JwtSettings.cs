using System;
using System.Collections.Generic;
using System.Text;

namespace JsonWebToken.Core.Authentication.Models
{
    public class JwtSettings
    {
        public string TokenType { get; set; }
        public string PublicCertificatePathName { get; set; }
        public string PrivateKeyPathName { get; set; }
        public JwtTokenSettings JwtTokenSettings { get; set; }
    }
}
