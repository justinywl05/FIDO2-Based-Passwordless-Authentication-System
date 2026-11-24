using System.ComponentModel.DataAnnotations;
using Fido2NetLib;

namespace NexusUniversityWebPortal.AuthBackend.ViewModels
{
    /// <summary>
    /// Request payload for the student to submit their FIDO2 attestation response
    /// during the initial admin-verified registration (Phase 1: Root of Trust).
    /// </summary>
    public class InitialVerifyRequest
    {
        /// <summary>
        /// The one-time registration token from the QR code URL.
        /// This links the verification back to the admin-initiated session.
        /// </summary>
        [Required]
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// A friendly name for the device being registered (e.g. "Justin's iPhone").
        /// </summary>
        [Required]
        public string DeviceName { get; set; } = string.Empty;

        /// <summary>
        /// The type of the device (e.g. "Mobile", "Web", "Security Key").
        /// </summary>
        [Required]
        public string DeviceType { get; set; } = string.Empty;

        /// <summary>
        /// The raw attestation response from navigator.credentials.create().
        /// </summary>
        [Required]
        public System.Text.Json.JsonElement AttestationResponse { get; set; }
    }
}
