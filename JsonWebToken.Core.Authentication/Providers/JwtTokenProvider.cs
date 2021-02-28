using JsonWebToken.Core.Authentication.Helpers;
using JsonWebToken.Core.Authentication.Models;
using JsonWebToken.Core.Authentication.Providers.Interfaces;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JsonWebToken.Core.Authentication.Providers
{
    public class JwtTokenProvider : IJwtTokenProvider
    {
        public string TokenType { get; set; }
        private readonly JwtSettings _jwtSettings;

        public JwtTokenProvider(IOptions<JwtSettings> jwtSettings)
        {
            _jwtSettings = jwtSettings.Value;
            TokenType = _jwtSettings.TokenType;
        }

        public string CreateToken(IEnumerable<Claim> claims)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.JwtTokenSettings.Expires),
                SigningCredentials = JwtSecurity.GetPrivateSigningCredential(_jwtSettings),
                Audience = _jwtSettings.JwtTokenSettings.ValidateAudience ? _jwtSettings.JwtTokenSettings.ValidAudience : null,
                Issuer = _jwtSettings.JwtTokenSettings.ValidateIssuer ? _jwtSettings.JwtTokenSettings.ValidIssuer : null,
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public bool ValidateToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenValidationParameters = TokenValidation.TokenParameter(_jwtSettings, JwtSecurity.GetPublicSigningCredential(_jwtSettings));
            try
            {
                tokenHandler.ValidateToken(token.Replace($"{_jwtSettings.TokenType} ", ""), tokenValidationParameters, out SecurityToken securityToken);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
