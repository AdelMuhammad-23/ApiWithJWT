using ApiWithJWT.Models;

namespace ApiWithJWT.Servies
{
    public interface IAuthServies
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> LoginAsync(TokenRequestModel model);
        Task<string> AddRoleAsync(AddRoleModel model);
    }
}
