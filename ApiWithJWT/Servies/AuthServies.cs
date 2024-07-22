using ApiWithJWT.Helpers;
using ApiWithJWT.Models;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ApiWithJWT.Servies
{
    public class AuthServies : IAuthServies
    {
        //Verify the validity of the information that the user enters
        private readonly UserManager<ApplicationUser> _userManager;
        // Verification of operations for identity
        private readonly RoleManager<IdentityRole> _roleManager;

        private readonly JwtOptions _jwt;

        public AuthServies(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, JwtOptions jwt)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt;
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthModel { Message = " Email is already regiestered " };
            if (await _userManager.FindByNameAsync(model.UserName) is not null)
                return new AuthModel { Message = " User Name is already regiestered " };

            var newUser = new ApplicationUser
            {
                UserName = model.UserName,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
            };

            var result = await _userManager.CreateAsync(newUser, model.Password);
            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in result.Errors)
                {
                    errors += $"{error.Description} \n";
                }
                return new AuthModel { Message = errors };
            }
            await _userManager.AddToRoleAsync(newUser, "User");

            var jwtSecurityToken = await CreateJwtToken(newUser);

            return new AuthModel
            {
                Email = newUser.Email,
                IsAuthenticated = true,
                ExpiresOn = jwtSecurityToken.ValidTo,
                Role = new List<string> { "User" },
                UserName = newUser.UserName,
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken)
            };
        }


        public async Task<AuthModel> LoginAsync(TokenRequestModel model)
        {
            var authModel = new AuthModel();

            var user = await _userManager.FindByEmailAsync(model.Email);
            var userPassword = await _userManager.CheckPasswordAsync(user , model.Password);

            if (user is null || !userPassword )
            {
                authModel.Message = "Email or Password is not correct!";
                return authModel;
            }
            var jwtSecurityToken = await CreateJwtToken(user);
            var roleList = await _userManager.GetRolesAsync(user);

            authModel.Email = user.Email;
            authModel.ExpiresOn = jwtSecurityToken.ValidTo;
            authModel.IsAuthenticated = true;
            authModel.UserName = user.UserName;
            authModel.Role = roleList.ToList();
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

            return authModel;
        }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user is null || !await _roleManager.RoleExistsAsync(model.RoleName))
                return "invalid User Id or Role !! ";

            if (await _userManager.IsInRoleAsync(user, model.RoleName))
                return "User already assigned in this role";

            var result = await _userManager.AddToRoleAsync(user , model.RoleName);

            return result.Succeeded ? string.Empty : "Something went wrong!";
        }



        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
            {
                var userClaims = await _userManager.GetClaimsAsync(user);
                var roles = await _userManager.GetRolesAsync(user);
                var roleClaims = new List<Claim>();

                foreach (var role in roles)
                    roleClaims.Add(new Claim("roles", role));

                var claims = new[]
                {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
                .Union(userClaims)
                .Union(roleClaims);

                var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.SigningKey));
                var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

                var jwtSecurityToken = new JwtSecurityToken(
                    issuer: _jwt.Issuer,
                    audience: _jwt.Audience,
                    claims: claims,
                    expires: DateTime.Now.AddDays(_jwt.Lifetime),
                    signingCredentials: signingCredentials);

                return jwtSecurityToken;
            }

       
    }
    } 
