using JsonWebToken.Core.Authentication.Helpers;
using JsonWebToken.Core.Authentication.Models;
using JsonWebToken.Core.Authentication.Providers;
using JsonWebToken.Core.Authentication.Providers.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Threading.Tasks;

namespace JsonWebToken.Core.Authentication
{
    public static class JwtConfigurationExtensions
    {
        public static void JwtConfiguration(this IServiceCollection services, IConfiguration configuration)
        {
            var tokenSection = configuration.GetSection("JwtSettings");
            var tokenSettings = tokenSection.Get<JwtSettings>();

            services.Configure<JwtSettings>(tokenSection);
            services.AddScoped<IJwtTokenProvider, JwtTokenProvider>();

            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
           .AddJwtBearer(x =>
           {
               x.Events = new JwtBearerEvents
               {
                   //It is the first event that meets and accepts all requests from the Client, whether token or not.
                   OnMessageReceived = context =>
                   {
                       return Task.CompletedTask;
                   },
                   //If the token sent with the request is valid, it is triggered and verification procedures are performed
                   OnTokenValidated = context =>
                   {
                       return Task.CompletedTask;
                   },
                   //The token that came with the request is invalid, worn or corrupted
                   OnAuthenticationFailed = context =>
                   {
                       return Task.CompletedTask;
                   },
                   OnChallenge = context =>
                   {
                       return Task.CompletedTask;
                   }

               };
               x.RequireHttpsMetadata = false;
               x.SaveToken = true;
               x.TokenValidationParameters = TokenValidation.TokenParameter(tokenSettings, JwtSecurity.GetPublicSigningCredential(tokenSettings));
           });
        }
    }
}
