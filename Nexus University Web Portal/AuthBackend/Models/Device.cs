using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace NexusUniversityWebPortal.AuthBackend.Models
{
    public class Device
    {
        [Key]
        public Guid DeviceId { get; set; } = Guid.NewGuid();
        
        public Guid UserId { get; set; }
        public User? User { get; set; }
        
        public string DeviceName { get; set; } = string.Empty;
        public string DeviceType { get; set; } = string.Empty;
        
        public DateTime RegisteredAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastUsedAt { get; set; }
        public string Status { get; set; } = "Active";

        public ICollection<Credential> Credentials { get; set; } = new List<Credential>();
    }
}
