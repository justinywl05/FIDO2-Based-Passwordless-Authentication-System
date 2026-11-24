using Fido2NetLib;

namespace NexusUniversityWebPortal.AuthBackend.ViewModels
{
    /// <summary>
    /// Response payload containing the FIDO2 credential create options.
    /// </summary>
    public class RegisterOptionsResponse
    {
        public string Status { get; set; } = "ok";
        public string ErrorMessage { get; set; } = string.Empty;
        
        /// <summary>
        /// FIDO2 options to be passed to navigator.credentials.create()
        /// </summary>
        public CredentialCreateOptions? Options { get; set; }
    }
}
