using System;
using System.Text.Json;

namespace NexusUniversityWebPortal.AuthBackend.ViewModels
{
    public class LoginVerifyRequest
    {
        public string Email { get; set; } = string.Empty;
        public JsonElement AssertionResponse { get; set; }
    }
}
