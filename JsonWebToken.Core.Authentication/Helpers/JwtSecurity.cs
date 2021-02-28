using JsonWebToken.Core.Authentication.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace JsonWebToken.Core.Authentication.Helpers
{
    public class JwtSecurity
    {
        public static SigningCredentials GetPrivateSigningCredential(JwtSettings jwtSettings)
        {
            var fileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certificate", jwtSettings.PrivateKeyPathName);
            string privateKeyPem = File.ReadAllText(fileName);

            privateKeyPem = privateKeyPem.Replace("-----BEGIN PRIVATE KEY-----", "");
            privateKeyPem = privateKeyPem.Replace("-----END PRIVATE KEY-----", "");

            byte[] privateKeyRaw = Convert.FromBase64String(privateKeyPem);

            var provider = new RSACryptoServiceProvider();
            provider.ImportPkcs8PrivateKey(new ReadOnlySpan<byte>(privateKeyRaw), out _);
            var rsaSecurityKey = new RsaSecurityKey(provider);
            return new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256);
        }

        public static SecurityKey GetPublicSigningCredential(JwtSettings jwtSettings)
        {
            var fileName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certificate", jwtSettings.PublicCertificatePathName);
            var cert = new X509Certificate2(fileName);
            var rsaSecurityKey = new RsaSecurityKey(cert.GetRSAPublicKey());
            return rsaSecurityKey;
        }
    }
}
