using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MyShoppingCart.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MyShoppingCart.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _configuration;

        public AuthService(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
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
            var key = Encoding.ASCII.GetBytes(_configuration.GetSection("Jwt:Key").Value);

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
    }
}
