using System;
using System.Threading.Tasks;
using NexusUniversityWebPortal.AuthBackend.Data;
using NexusUniversityWebPortal.AuthBackend.Models;

namespace NexusUniversityWebPortal.AuthBackend.Services
{
    /// <summary>
    /// Service for logging authentication-related actions into the AuditLogs table.
    /// </summary>
    public class AuditLogService
    {
        private readonly ApplicationDbContext _context;

        public AuditLogService(ApplicationDbContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Logs an action to the database.
        /// </summary>
        /// <param name="action">The action being logged (e.g., "Register Success").</param>
        /// <param name="details">Additional details about the action.</param>
        /// <param name="userId">The ID of the user performing the action, if applicable.</param>
        /// <param name="deviceId">The ID or name of the device involved, if applicable.</param>
        /// <param name="ipAddress">The IP address of the client.</param>
        public async Task LogAsync(string action, string details, Guid? userId = null, string? deviceId = null, string? ipAddress = null)
        {
            var auditLog = new AuditLog
            {
                Action = action,
                Details = details,
                UserId = userId,
                DeviceId = deviceId,
                IpAddress = ipAddress,
                CreatedAt = DateTime.UtcNow
            };

            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
        }
    }
}
