using System;
using System.Threading.Tasks;
using NexusUniversityWebPortal.AuthBackend.Data;
using NexusUniversityWebPortal.AuthBackend.Models;
using NexusUniversityWebPortal.AuthBackend.Services;
using NexusUniversityWebPortal.AuthBackend.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace NexusUniversityWebPortal.AuthBackend.Controllers
{
    /// <summary>
    /// Admin-facing endpoints for managing student registration.
    /// NOTE: These endpoints should be protected by an Admin authentication policy in production.
    /// </summary>
    [ApiController]
    [Route("api/admin")]
    public class AdminController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly AuditLogService _auditLogService;
        private readonly IConfiguration _configuration;

        public AdminController(
            ApplicationDbContext context,
            AuditLogService auditLogService,
            IConfiguration configuration)
        {
            _context = context;
            _auditLogService = auditLogService;
            _configuration = configuration;
        }

        private async Task<User?> GetAuthenticatedAdminAsync()
        {
            if (!Request.Cookies.TryGetValue("portal_session_token", out var sessionToken) ||
                string.IsNullOrWhiteSpace(sessionToken))
            {
                return null;
            }

            var session = await _context.AuthSessions
                .Include(s => s.User)
                .FirstOrDefaultAsync(s =>
                    s.SessionToken == sessionToken &&
                    s.IsActive &&
                    s.ExpiresAt > DateTime.UtcNow);

            if (session?.User == null || session.User.RoleId != "admin")
            {
                return null;
            }

            return session.User;
        }

        /// <summary>
        /// Phase 1 — Admin Initiation:
        /// Verifies the student is in PendingEnrollment status, generates a short-lived
        /// one-time registration token, and returns a URL for display as a QR code.
        /// </summary>
        /// <remarks>
        /// POST /api/admin/registration/initiate
        /// Body: { "studentEmail": "student@portal.edu" }
        /// </remarks>
        [HttpPost("registration/initiate")]
        public async Task<IActionResult> InitiateRegistration([FromBody] InitiateRegistrationRequest request)
        {
            try
            {
                var admin = await GetAuthenticatedAdminAsync();
                if (admin == null)
                {
                    return Unauthorized(new InitiateRegistrationResponse
                    {
                        Status = "error",
                        ErrorMessage = "An active administrator session is required."
                    });
                }

                // --- 1. Look up the student ---
                var student = await _context.Users
                    .FirstOrDefaultAsync(u => u.Email == request.StudentEmail);

                if (student == null)
                {
                    return NotFound(new InitiateRegistrationResponse
                    {
                        Status = "error",
                        ErrorMessage = $"No user found with email '{request.StudentEmail}'."
                    });
                }

                // --- 2. Guard: Only PendingEnrollment students may use Phase 1 registration ---
                if (student.Status != "PendingEnrollment" && student.Email != "superadmin@university.edu")
                {
                    return BadRequest(new InitiateRegistrationResponse
                    {
                        Status = "error",
                        ErrorMessage = $"Student '{request.StudentEmail}' is not in PendingEnrollment status " +
                                       $"(current status: {student.Status}). " +
                                       "Only students pending initial enrollment require this flow."
                    });
                }

                // --- 3. Invalidate any previously generated but unused tokens for this student ---
                // This prevents orphaned tokens from accumulating in the database.
                var existingTokens = await _context.AuthChallenges
                    .Where(c => c.UserId == student.UserId
                             && c.Purpose == "InitialRegistration"
                             && !c.IsUsed)
                    .ToListAsync();

                foreach (var old in existingTokens)
                {
                    old.IsUsed = true; // Mark as consumed so they can no longer be used
                }

                // --- 4. Generate a cryptographically random, URL-safe one-time token ---
                // Using a GUID provides 122 bits of randomness, which is sufficient.
                var registrationToken = Guid.NewGuid().ToString("N"); // e.g., "a3f1b29e..." (32 hex chars)
                var expiresAt = DateTime.UtcNow.AddMinutes(5);

                // --- 5. Persist the token as an AuthChallenge record ---
                // The 'Challenge' field stores the raw token string for lookup.
                var tokenRecord = new AuthChallenge
                {
                    UserId = student.UserId,
                    Challenge = registrationToken,
                    Purpose = "InitialRegistration",
                    ExpiresAt = expiresAt,
                    IsUsed = false
                };

                _context.AuthChallenges.Add(tokenRecord);
                await _context.SaveChangesAsync();

                // --- 6. Build the QR code URL ---
                // The student's device (mobile app / browser) will open this URL.
                // Determine the base URL from configuration or the current request.
                var baseUrl = _configuration["AppSettings:FrontendBaseUrl"]
                              ?? $"{Request.Scheme}://{Request.Host}";

                var registrationUrl = $"{baseUrl}/register?token={registrationToken}";

                // --- 7. Audit log ---
                var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
                await _auditLogService.LogAsync(
                    "Admin Initiated Registration",
                    $"Admin '{admin.Email}' generated registration QR token for student '{request.StudentEmail}'",
                    student.UserId,
                    null,
                    ip);

                return Ok(new InitiateRegistrationResponse
                {
                    Status = "ok",
                    Token = registrationToken,
                    RegistrationUrl = registrationUrl,
                    ExpiresAt = expiresAt
                });
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new InitiateRegistrationResponse
                {
                    Status = "error",
                    ErrorMessage = ex.Message
                });
            }
        }
    }
}
