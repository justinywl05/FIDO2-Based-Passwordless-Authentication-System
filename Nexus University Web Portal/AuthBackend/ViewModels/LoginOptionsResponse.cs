using System;
using Fido2NetLib;

namespace NexusUniversityWebPortal.AuthBackend.ViewModels
{
    public class LoginOptionsResponse
    {
        public string Status { get; set; } = "error";
        public string ErrorMessage { get; set; } = string.Empty;
        public AssertionOptions? Options { get; set; }
    }
}
