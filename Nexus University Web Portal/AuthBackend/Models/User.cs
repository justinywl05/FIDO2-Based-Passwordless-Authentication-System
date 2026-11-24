using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace NexusUniversityWebPortal.AuthBackend.Models
{
    public class User
    {
        [Key]
        public Guid UserId { get; set; } = Guid.NewGuid();
        public string Email { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public string StudentStaffId { get; set; } = string.Empty;
        public string Status { get; set; } = "PendingEnrollment";
        public string RoleId { get; set; } = "student";
        public string PhoneNo { get; set; } = string.Empty;
        public string Address { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Navigation Properties
        public ICollection<Device> Devices { get; set; } = new List<Device>();
        public ICollection<AuthSession> AuthSessions { get; set; } = new List<AuthSession>();
    }
}
