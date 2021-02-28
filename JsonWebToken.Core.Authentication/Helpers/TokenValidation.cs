using JsonWebToken.Core.Authentication.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace JsonWebToken.Core.Authentication.Helpers
{
    public class TokenValidation
    {
        public static TokenValidationParameters TokenParameter(JwtSettings jwtSettings, SecurityKey securityKey)
        {
            return new TokenValidationParameters
            {
                ValidateIssuerSigningKey = jwtSettings.JwtTokenSettings.ValidateIssuerSigningKey,
                IssuerSigningKey = securityKey,
                ValidateLifetime = jwtSettings.JwtTokenSettings.ValidateLifetime,
                ValidateIssuer = jwtSettings.JwtTokenSettings.ValidateIssuer,
                ValidIssuer = jwtSettings.JwtTokenSettings.ValidateIssuer ? jwtSettings.JwtTokenSettings.ValidIssuer : null,
                ValidateAudience = jwtSettings.JwtTokenSettings.ValidateAudience,
                ValidAudience = jwtSettings.JwtTokenSettings.ValidateAudience ? jwtSettings.JwtTokenSettings.ValidAudience : null,
                ClockSkew = TimeSpan.FromMinutes(jwtSettings.JwtTokenSettings.ClockSkew)
            };
        }
    }
}
