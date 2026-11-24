using System;
using System.ComponentModel.DataAnnotations;

namespace NexusUniversityWebPortal.AuthBackend.Models
{
    public class AuthChallenge
    {
        [Key]
        public Guid ChallengeId { get; set; } = Guid.NewGuid();
        
        public Guid? UserId { get; set; }
        
        public string Challenge { get; set; } = string.Empty;
        public string Purpose { get; set; } = string.Empty; // "Register" or "Login"
        
        public DateTime ExpiresAt { get; set; }
        public bool IsUsed { get; set; } = false;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
