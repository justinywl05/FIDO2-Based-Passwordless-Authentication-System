using System.ComponentModel.DataAnnotations;
using Fido2NetLib;

namespace NexusUniversityWebPortal.AuthBackend.ViewModels
{
    /// <summary>
    /// Request payload for verifying a FIDO2 registration attestation.
    /// </summary>
    public class RegisterVerifyRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string DeviceName { get; set; } = string.Empty;

        [Required]
        public string DeviceType { get; set; } = string.Empty;

        /// <summary>
        /// The raw response from navigator.credentials.create() mapped by Fido2NetLib.
        /// </summary>
        [Required]
        public AuthenticatorAttestationRawResponse AttestationResponse { get; set; } = null!;
    }
}
