using System.Collections.Generic;
using System.Security.Claims;

namespace JsonWebToken.Core.Authentication.Providers.Interfaces
{
    public interface IJwtTokenProvider
    {
        string TokenType { get; set; }
        string CreateToken(IEnumerable<Claim> claims);
        bool ValidateToken(string token);
    }
}
