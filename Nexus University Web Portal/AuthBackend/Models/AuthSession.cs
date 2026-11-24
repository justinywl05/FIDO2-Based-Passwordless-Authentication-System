using System;
using System.ComponentModel.DataAnnotations;

namespace NexusUniversityWebPortal.AuthBackend.Models
{
    public class AuthSession
    {
        [Key]
        public Guid AuthSessionId { get; set; } = Guid.NewGuid();
        
        public Guid UserId { get; set; }
        public User? User { get; set; }
        
        public Guid? DeviceId { get; set; }
        public Device? Device { get; set; }

        public string SessionToken { get; set; } = string.Empty;
        
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
        
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresAt { get; set; }
        public DateTime? RevokedAt { get; set; }
        public bool IsActive { get; set; } = true;
    }
}
