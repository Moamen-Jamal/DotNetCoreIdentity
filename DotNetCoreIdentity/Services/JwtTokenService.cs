using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;

namespace DotNetCoreIdentity.Services
{
    public class JwtTokenService
    {
        private readonly IConfiguration _configuration;

        public JwtTokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public (string token, DateTime expiresUtc) GenerateToken(string userId, string email, IEnumerable<string>? roles = null, IEnumerable<Claim>? extraClaims = null)
        {
            var jwtSection = _configuration.GetSection("Jwt");
            var issuer = jwtSection["Issuer"] ?? string.Empty;
            var audience = jwtSection["Audience"] ?? string.Empty;
            var key = jwtSection["Key"] ?? throw new InvalidOperationException("JWT Key not configured");

            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.UniqueName, email),
                new Claim(JwtRegisteredClaimNames.Email, email)
            };

            if (roles != null)
            {
                foreach (var role in roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }
            }
            if (extraClaims != null)
            {
                claims.AddRange(extraClaims);
            }

            var expires = DateTime.UtcNow.AddHours(1);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: expires,
                signingCredentials: credentials
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            return (tokenString, expires);
        }
    }
}


