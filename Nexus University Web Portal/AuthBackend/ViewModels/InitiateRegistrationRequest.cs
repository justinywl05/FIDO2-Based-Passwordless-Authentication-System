using System.ComponentModel.DataAnnotations;

namespace NexusUniversityWebPortal.AuthBackend.ViewModels
{
    /// <summary>
    /// Request payload for an administrator to initiate the initial physical registration of a student.
    /// </summary>
    public class InitiateRegistrationRequest
    {
        /// <summary>
        /// The email address of the student whose registration is being initiated.
        /// </summary>
        [Required]
        [EmailAddress]
        public string StudentEmail { get; set; } = string.Empty;
    }
}
