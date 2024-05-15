using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MyShoppingCart.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

namespace MyShoppingCart.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailSender _emailSender;
        //private readonly UserStore<IdentityUser> _userStore;

        public AuthService
        (
            UserManager<IdentityUser> userManager, 
            SignInManager<IdentityUser> signInManager, 
            IConfiguration configuration, 
            IEmailSender emailSender 
            //UserStore<IdentityUser> userStore
        )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _emailSender = emailSender;
            //_userStore = userStore;
        }
        public async Task<bool> RegisterUserAsync(UserRegister userRegister)
        {
            var identityUser = new IdentityUser
            {
                UserName = userRegister.UserName,
                Email = userRegister.Email,
                PhoneNumber = userRegister.PhoneNumber,
                EmailConfirmed = false
            };
            var result = await _userManager.CreateAsync(identityUser, userRegister.Password);
            var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, identityUser.UserName),
                    new Claim(ClaimTypes.Email, identityUser.Email)
                };
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration.GetSection("Jwt:Key").Value);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(5),
                Issuer = _configuration.GetSection("Jwt:Issuer").Value,
                Audience = _configuration.GetSection("Jwt:Issuer").Value,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);
            string emailSubject = "Confirm your registration";
            string httpMessage = $"Please confirm your account by <a href='https://localhost:7046/api/RegisterConfirm?token={tokenString}'>clicking here</a>.";
            await _emailSender.SendEmailAsync(identityUser.Email, emailSubject, httpMessage);
            
            return result.Succeeded;
        }
        public async Task<bool> LoginAsync(UserLogin userLogin)
        {
            var identityUser = await _userManager.FindByEmailAsync(userLogin.Email);
            if(identityUser == null)
            {
                return false;
            }
            else if (!await _userManager.CheckPasswordAsync(identityUser, userLogin.Password))
            {
                return false;
            }
            await _signInManager.SignInAsync(identityUser, false);
            return true;
        }

        public async Task<string?> GenerateTokenStringAsync(UserLogin userLogin)
        {
            var identityUser = await _userManager.FindByEmailAsync(userLogin.Email);
            if(identityUser == null)
            {
                return null;
            }
            var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, identityUser.UserName),
                    new Claim(ClaimTypes.Email, identityUser.Email)
                };
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration.GetSection("Jwt:Key").Value);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(15),
                Issuer = _configuration.GetSection("Jwt:Issuer").Value,
                Audience = _configuration.GetSection("Jwt:Issuer").Value,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            return tokenString;
        }

        //public async Task<bool> RegisterConfirmAsync(string token)
        //{
        //    string[] tokenSplit = token.Split('.');
        //    string encodedBody = tokenSplit[0] + "."+ tokenSplit[1];
        //    string signature = tokenSplit[2];
        //    string newSignature = "";
        //    byte[] key = Encoding.UTF8.GetBytes(_configuration.GetSection("Jwt:Key").Value);
        //    using (HMACSHA256 hmac = new HMACSHA256(key))
        //    {
        //        byte[] signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(encodedBody));
        //        newSignature = Encoding.UTF8.GetString(signatureBytes);
        //    }
        //    if(newSignature != signature)
        //    {
        //        return false;
        //    }
        //    var handler = new JwtSecurityTokenHandler();
        //    var jwtToken = handler.ReadJwtToken(token);
        //    var identityUser = await _userManager.FindByEmailAsync(jwtToken.Claims.First(c => c.Type == "email").Value);
        //    if(identityUser == null) 
        //    {
        //        return false;
        //    }
        //    await _userStore.SetEmailConfirmedAsync(identityUser, true);
        //    return true;
        //}
    }
}
