using Cafe_Management_System.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Web;

namespace Cafe_Management_System
{
    public class TokenManager
    {
        // Make sure this key is at least 16 bytes long for HMACSHA256
        public static string Secrect = "randomwordswhichlengthwillbefiftytobesecuredbhbhhhuhoyghi";
        //Generate Tokens
        public static string GenerateToken(string email,string role)
        {
            // Create a security key from the secret
            SymmetricSecurityKey securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secrect));
            // Define token descriptor
            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Email, email), new Claim(ClaimTypes.Role, role) }),
                Expires = DateTime.UtcNow.AddHours(8),
                SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature)
            };
            // Create the token
            JwtSecurityTokenHandler handler =new JwtSecurityTokenHandler();
            JwtSecurityToken token = handler.CreateJwtSecurityToken(descriptor);
            // Return the serialized token
            return handler.WriteToken(token);
        }
        //
        public static ClaimsPrincipal GetPrincipal(string token)
        {
            try { 
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                JwtSecurityToken jwtToken = (JwtSecurityToken)tokenHandler.ReadToken(token);
                if (jwtToken == null)
                {
                    return null;
                }
                TokenValidationParameters parameters = new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secrect))
                };
                SecurityToken securityToken;
                ClaimsPrincipal principal = tokenHandler.ValidateToken(token,parameters,out securityToken);
                return principal;

            }
            catch(Exception e)
            {
                return null;
            }
        }

        public static TokenClaim ValidateToken(string RawToken)
        {
            string[] array = RawToken.Split(' ');
            var token = array[1];
            ClaimsPrincipal principal = GetPrincipal(token);
            if(principal== null)
            {
                return null;
            }
            ClaimsIdentity identity = null;
            try {
                identity = (ClaimsIdentity)principal.Identity;
            }
            catch(Exception e)
            {
                return null;
            }
            TokenClaim tokenClaim = new TokenClaim();
            var temp = identity.FindFirst(ClaimTypes.Email);
            tokenClaim.Email = temp.Value;
            temp=identity.FindFirst(ClaimTypes.Role);
            tokenClaim.Role= temp.Value;
            return tokenClaim;
        }
    }
}