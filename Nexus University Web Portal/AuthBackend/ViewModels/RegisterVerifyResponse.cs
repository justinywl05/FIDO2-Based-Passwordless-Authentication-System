namespace NexusUniversityWebPortal.AuthBackend.ViewModels
{
    /// <summary>
    /// Response payload indicating the success or failure of the registration verification.
    /// </summary>
    public class RegisterVerifyResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}
