using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MyShoppingCart.Models;
using MyShoppingCart.Services;

namespace MyShoppingCart.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }
        [HttpPost("Register")]
        public async Task<IActionResult> RegisterUserAsync(UserRegister userRegister)
        {
            if(await _authService.RegisterUserAsync(userRegister))
                return Ok("Register User Successfully");
            return BadRequest("Register failed");
        }
        [HttpPost("Login")]
        public async Task<IActionResult> LoginAsync(UserLogin userLogin)
        {
            //if (await _authService.LoginAsync(userLogin))
            //    return Ok("Login Successfully");
            //return BadRequest("Login failed");
            var token = await _authService.GenerateTokenStringAsync(userLogin);
            if (token == null)
                return BadRequest("Login failed");
            return Ok(token);
        }
        //[HttpGet("RegisterConfirm")]
        //public async Task<IActionResult> RegisterConfirm(string token)
        //{
        //    if (await _authService.RegisterConfirmAsync(token))
        //        return Ok("Confirmed successfully");
        //    return BadRequest("Not yet confirmed");
        //}
    }
}
