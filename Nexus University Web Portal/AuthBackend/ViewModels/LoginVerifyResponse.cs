using System;

namespace NexusUniversityWebPortal.AuthBackend.ViewModels
{
    public class LoginVerifyResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}
