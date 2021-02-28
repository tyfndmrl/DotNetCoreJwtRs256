using JsonWebToken.Core.Authentication.Providers.Interfaces;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JsonWebToken.Core.RSA256.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IJwtTokenProvider _jwtTokenProvider;
        public UserController(IJwtTokenProvider jwtTokenProvider)
        {
            _jwtTokenProvider = jwtTokenProvider;
        }

        [HttpGet("token/generate")]
        [AllowAnonymous]
        public IActionResult GenerateToken()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, "1"),
                new Claim(ClaimTypes.Name, "userName"),
                new Claim("FirstName","firstName"),
                new Claim("LastName","lastName"),
                new Claim(ClaimTypes.Email, "test@email.com"),
            };

            var token = _jwtTokenProvider.CreateToken(claims);

            return Ok(new
            {
                _jwtTokenProvider.TokenType,
                Token = token,
            });
        }

        [HttpGet("token/validate")]
        [AllowAnonymous]
        public IActionResult ValidateToken(string token)
        {
            var valid = _jwtTokenProvider.ValidateToken(token);
            if (valid)
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadToken(token) as JwtSecurityToken;
                return Ok(new
                {
                    jwtToken.Claims
                });
            }

            return BadRequest("Token is invalid.");
        }

        [HttpGet("token/validateHeader")]
        public IActionResult ValidateTokenHeader()
        {
            var token = Request.HttpContext.GetTokenAsync("access_token").Result;
            var valid = _jwtTokenProvider.ValidateToken(token);
            if (valid)
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadToken(token) as JwtSecurityToken;
                return Ok(new
                {
                    jwtToken.Claims
                });
            }

            return BadRequest("Token is invalid.");
        }
    }
}
