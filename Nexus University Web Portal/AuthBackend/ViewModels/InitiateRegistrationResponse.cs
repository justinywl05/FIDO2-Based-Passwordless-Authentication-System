using System;

namespace NexusUniversityWebPortal.AuthBackend.ViewModels
{
    /// <summary>
    /// Response payload returned to the administrator after initiating a student's registration.
    /// Contains a short-lived registration URL suitable for embedding in a QR code.
    /// </summary>
    public class InitiateRegistrationResponse
    {
        public string Status { get; set; } = "ok";
        public string ErrorMessage { get; set; } = string.Empty;

        /// <summary>
        /// The one-time registration token. Embed this URL as a QR code for the student to scan.
        /// </summary>
        public string RegistrationUrl { get; set; } = string.Empty;

        /// <summary>
        /// The raw token value (useful for debugging or custom QR code generation).
        /// </summary>
        public string Token { get; set; } = string.Empty;

        /// <summary>
        /// UTC expiry time of the registration token.
        /// </summary>
        public DateTime ExpiresAt { get; set; }
    }
}
