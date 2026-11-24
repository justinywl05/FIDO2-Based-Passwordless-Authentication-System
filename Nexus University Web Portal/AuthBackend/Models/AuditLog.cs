using System;
using System.ComponentModel.DataAnnotations;

namespace NexusUniversityWebPortal.AuthBackend.Models
{
    public class AuditLog
    {
        [Key]
        public Guid AuditLogId { get; set; } = Guid.NewGuid();
        
        public string Action { get; set; } = string.Empty; 
        public string Details { get; set; } = string.Empty;
        
        public Guid? UserId { get; set; }
        public string? DeviceId { get; set; }

        public string? IpAddress { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [System.ComponentModel.DataAnnotations.Schema.NotMapped]
        public string? UserEmail { get; set; }
    }
}
