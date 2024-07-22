using ApiWithJWT.Models;
using ApiWithJWT.Servies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace ApiWithJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
       
            public readonly IAuthServies _authServies;

            public AuthController(IAuthServies authServies)
            {
                _authServies = authServies;
            }

            [HttpPost("register")]
            public async Task<IActionResult> LoginAsync([FromBody] RegisterModel model)
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                var result = await _authServies.RegisterAsync(model);

                if (!result.IsAuthenticated)
                    return BadRequest(result.Message);
                return Ok(result);
            } 
            
            
            [HttpPost("login")]
            public async Task<IActionResult> LoginAsync ([FromBody] TokenRequestModel model)
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                var result = await _authServies.LoginAsync(model);

                if (!result.IsAuthenticated)
                    return BadRequest(result.Message);


                return Ok(result);
            }

            [HttpPost("addToRole")]
            public async Task<IActionResult> AddToRoleAsync ([FromBody] AddRoleModel model)
            {
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                var result = await _authServies.AddRoleAsync(model);

                if (!string.IsNullOrEmpty(result))
                    return BadRequest(result);


                return Ok(model);
            }
        }
}
