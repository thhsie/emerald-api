
using System.ComponentModel.DataAnnotations;

namespace Emerald.Api.ViewModels
{
    public class RegisterUserViewModel
    {
        [Required(ErrorMessage = "The field {0} is required")]
        [EmailAddress(ErrorMessage = "The field {0} is in an invalid format")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "The field {0} is required")]
        [StringLength(100, ErrorMessage = "The field {0} must be between {2} and {1} characters", MinimumLength = 6)]
        public string Password { get; set; } = string.Empty;
        
        [Required(ErrorMessage = "The field {0} is required")]
        [Compare("Password", ErrorMessage = "The passwords do not match")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public class LoginUserViewModel
    {
        [Required(ErrorMessage = "The field {0} is required")]
        [EmailAddress(ErrorMessage = "The field {0} is in an invalid format")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "The field {0} is required")]
        [StringLength(100, ErrorMessage = "The field {0} must be between {2} and {1} characters", MinimumLength = 6)]
        public string Password { get; set; } = string.Empty;
    }

    public class LoginResponseViewModel
    {
        public string AccessToken { get; set; } = string.Empty;
        public double ExpiresIn { get; set; }
    }
}