using System;
using System.ComponentModel.DataAnnotations;

namespace NexusUniversityWebPortal.AuthBackend.Models
{
    public class Credential
    {
        [Key]
        public byte[] CredentialId { get; set; } = Array.Empty<byte>(); // Maps to FIDO Descriptor ID
        
        public Guid UserId { get; set; }
        public User? User { get; set; }

        public Guid DeviceId { get; set; }
        public Device? Device { get; set; }

        public byte[] PublicKey { get; set; } = Array.Empty<byte>();
        public uint SignCount { get; set; }
        
        public string Transports { get; set; } = string.Empty;
        public string AttestationFormat { get; set; } = string.Empty;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastUsedAt { get; set; }
        public string Status { get; set; } = "Active";
    }
}
