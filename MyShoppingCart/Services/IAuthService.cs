using Microsoft.AspNetCore.Mvc;
using MyShoppingCart.Models;

namespace MyShoppingCart.Services
{
    public interface IAuthService
    {
        Task<bool> RegisterUserAsync(UserRegister userRegister);
        Task<bool> LoginAsync(UserLogin userLogin);
        Task<string?> GenerateTokenStringAsync(UserLogin userLogin);
        //Task<bool> RegisterConfirmAsync(string token);
    }
}
