using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace MyShoppingCart.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HomeController : ControllerBase
    {
        [HttpGet]
        public async Task<IActionResult> HomePage()
        {
            return Ok("Home Page");
        }
    }
}
