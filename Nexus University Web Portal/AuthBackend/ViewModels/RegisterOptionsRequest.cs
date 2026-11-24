using System.ComponentModel.DataAnnotations;

namespace NexusUniversityWebPortal.AuthBackend.ViewModels
{
    /// <summary>
    /// Request payload for generating FIDO2 registration options.
    /// </summary>
    public class RegisterOptionsRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string DeviceName { get; set; } = string.Empty;

        [Required]
        public string DeviceType { get; set; } = string.Empty;
    }
}
