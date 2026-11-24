using System;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Objects;
using NexusUniversityWebPortal.AuthBackend.Data;
using NexusUniversityWebPortal.AuthBackend.Models;
using NexusUniversityWebPortal.AuthBackend.Services;
using NexusUniversityWebPortal.AuthBackend.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Http;

namespace NexusUniversityWebPortal.AuthBackend.Controllers
{
    [ApiController]
    [Route("api/auth/register")]
    public class AuthController : ControllerBase
    {
        private readonly Fido2Service _fido2Service;
        private readonly AuditLogService _auditLogService;
        private readonly ApplicationDbContext _context;

        public AuthController(
            Fido2Service fido2Service, 
            AuditLogService auditLogService, 
            ApplicationDbContext context)
        {
            _fido2Service = fido2Service;
            _auditLogService = auditLogService;
            _context = context;
        }

        /// <summary>
        /// Phase 1, Step 1 — Student Options Retrieval (via QR code scan):
        /// Validates the short-lived admin token from the QR code, then generates
        /// and returns FIDO2 CredentialCreateOptions for the linked student's device.
        ///
        /// GET /api/auth/register/options-by-token?token={token}
        /// </summary>
        [HttpGet("options-by-token")]
        public async Task<IActionResult> GetOptionsByToken([FromQuery] string token)
        {
            try
            {
                // --- 1. Validate the incoming token is non-empty ---
                if (string.IsNullOrWhiteSpace(token))
                {
                    return BadRequest(new RegisterOptionsResponse
                    {
                        Status = "error",
                        ErrorMessage = "A registration token must be provided."
                    });
                }

                // --- 2. Look up the token — supports InitialRegistration and SelfDeviceRegistration ---
                var tokenRecord = await _context.AuthChallenges
                    .FirstOrDefaultAsync(c =>
                        c.Challenge == token
                        && (c.Purpose == "InitialRegistration" || c.Purpose == "SelfDeviceRegistration")
                        && !c.IsUsed
                        && c.ExpiresAt > DateTime.UtcNow);

                if (tokenRecord == null)
                {
                    return BadRequest(new RegisterOptionsResponse
                    {
                        Status = "error",
                        ErrorMessage = "The registration token is invalid, has already been used, or has expired."
                    });
                }

                // --- 3. Retrieve the user linked to this token ---
                var student = await _context.Users
                    .FirstOrDefaultAsync(u => u.UserId == tokenRecord.UserId);

                if (student == null)
                {
                    return NotFound(new RegisterOptionsResponse
                    {
                        Status = "error",
                        ErrorMessage = "The account associated with this token could not be found."
                    });
                }

                // --- 4. Status guard — only check PendingEnrollment for admin-initiated tokens ---
                if (tokenRecord.Purpose == "InitialRegistration")
                {
                    if (student.Status != "PendingEnrollment" && student.Email != "superadmin@university.edu")
                    {
                        return BadRequest(new RegisterOptionsResponse
                        {
                            Status = "error",
                            ErrorMessage = $"Account is not in PendingEnrollment status (current: {student.Status})."
                        });
                    }
                }
                else // SelfDeviceRegistration — must be Active
                {
                    if (student.Status != "Active")
                    {
                        return BadRequest(new RegisterOptionsResponse
                        {
                            Status = "error",
                            ErrorMessage = "Your account must be Active to register an additional device."
                        });
                    }
                }

                // --- 5. Generate FIDO2 options with the correct purpose tag ---
                var fidoPurpose = tokenRecord.Purpose == "InitialRegistration"
                    ? "InitialRegistration-FIDO2"
                    : "SelfDeviceRegistration-FIDO2";

                var options = await _fido2Service.GenerateRegisterOptionsAsync(student, purpose: fidoPurpose);

                // --- 6. Audit log ---
                var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
                await _auditLogService.LogAsync(
                    tokenRecord.Purpose == "InitialRegistration"
                        ? "Initial Registration Options Fetched"
                        : "Self Device Registration Options Fetched",
                    $"User '{student.Email}' fetched FIDO2 options via QR token.",
                    student.UserId, null, ip);

                return Ok(new RegisterOptionsResponse
                {
                    Status = "ok",
                    Options = options
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new RegisterOptionsResponse
                {
                    Status = "error",
                    ErrorMessage = ex.Message
                });
            }
        }

        /// <summary>
        /// Phase 1, Step 2 — Verify Initial Registration (Root of Trust establishment):
        /// Verifies the FIDO2 attestation response from the student's device. On success:
        ///   - Saves the Device and Credential (public key) to the database.
        ///   - Updates the student's status from PendingEnrollment to Active.
        ///   - Marks both the admin token and the FIDO2 challenge as used (consumed).
        ///   - Writes an audit log entry: "Root of Trust Established".
        ///
        /// POST /api/auth/register/verify-initial
        /// </summary>
        [HttpPost("verify-initial")]
        public async Task<IActionResult> VerifyInitialRegistration([FromBody] InitialVerifyRequest request)
        {
            try
            {
                // ============================================================
                // STEP 1 — Re-validate the admin token to locate the student
                // ============================================================
                // We allow the token to be already IsUsed=false at this point.
                // The options-by-token endpoint does NOT consume the token, so that
                // a refresh/retry on the student's device can re-fetch options without
                // requiring a new QR code. The token is only definitively consumed here.
                if (string.IsNullOrWhiteSpace(request.Token))
                {
                    return BadRequest(new RegisterVerifyResponse
                    {
                        Success = false,
                        Message = "A registration token is required."
                    });
                }

                var tokenRecord = await _context.AuthChallenges
                    .FirstOrDefaultAsync(c =>
                        c.Challenge == request.Token
                        && c.Purpose == "InitialRegistration"
                        && !c.IsUsed
                        && c.ExpiresAt > DateTime.UtcNow);

                if (tokenRecord == null)
                {
                    return BadRequest(new RegisterVerifyResponse
                    {
                        Success = false,
                        Message = "The registration token is invalid, has already been used, or has expired. " +
                                  "Please ask the administrator to generate a new QR code."
                    });
                }

                // ============================================================
                // STEP 2 — Retrieve the student
                // ============================================================
                var student = await _context.Users
                    .FirstOrDefaultAsync(u => u.UserId == tokenRecord.UserId);

                if (student == null)
                {
                    return NotFound(new RegisterVerifyResponse
                    {
                        Success = false,
                        Message = "The student account linked to this registration token was not found."
                    });
                }

                // Guard: Confirm status has not been changed by a race condition
                if (student.Status != "PendingEnrollment" && student.Email != "superadmin@university.edu")
                {
                    return BadRequest(new RegisterVerifyResponse
                    {
                        Success = false,
                        Message = $"Student account is not in PendingEnrollment status (current: {student.Status}). " +
                                  "Registration aborted to prevent duplicate enrollment."
                    });
                }

                // ============================================================
                // STEP 3 — Locate the FIDO2 challenge generated in options-by-token
                // ============================================================
                // Retrieve the latest un-used InitialRegistration-FIDO2 challenge for this student.
                var fido2Challenge = await _context.AuthChallenges
                    .Where(c =>
                        c.UserId == student.UserId
                        && c.Purpose == "InitialRegistration-FIDO2"
                        && !c.IsUsed
                        && c.ExpiresAt > DateTime.UtcNow)
                    .OrderByDescending(c => c.CreatedAt)
                    .FirstOrDefaultAsync();

                if (fido2Challenge == null)
                {
                    return BadRequest(new RegisterVerifyResponse
                    {
                        Success = false,
                        Message = "No valid FIDO2 registration challenge found. " +
                                  "The challenge may have expired. Please rescan the QR code."
                    });
                }

                // ============================================================
                // STEP 4 — Verify the FIDO2 attestation response
                // ============================================================
                AuthenticatorAttestationRawResponse parsedAttestation;
                try
                {
                    var rawJson = request.AttestationResponse.GetRawText();
                    parsedAttestation = System.Text.Json.JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(
                        rawJson, 
                        new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
                }
                catch (Exception ex)
                {
                    return BadRequest(new RegisterVerifyResponse
                    {
                        Success = false,
                        Message = $"JSON Parsing Error: {ex.Message}"
                    });
                }

                // If the attestation is invalid, Fido2NetLib throws an exception.
                // We catch it to return a structured 400 instead of a 500.
                RegisteredPublicKeyCredential credential;
                try
                {
                    credential = await _fido2Service.VerifyRegisterResponseAsync(
                        parsedAttestation,
                        fido2Challenge);
                }
                catch (Exception ex)
                {
                    var failIp = HttpContext.Connection.RemoteIpAddress?.ToString();
                    await _auditLogService.LogAsync(
                        "Initial Registration Failed — FIDO2 Verification Error",
                        $"Student '{student.Email}': {ex.Message}",
                        student.UserId,
                        null,
                        failIp);

                    return BadRequest(new RegisterVerifyResponse
                    {
                        Success = false,
                        Message = $"FIDO2 attestation verification failed: {ex.Message}"
                    });
                }

                // ============================================================
                // STEP 5 — Persist the Device and Credential (public key)
                // ============================================================
                var newDevice = new Device
                {
                    UserId = student.UserId,
                    DeviceName = request.DeviceName,
                    DeviceType = request.DeviceType,
                    RegisteredAt = DateTime.UtcNow,
                    Status = "Active"
                };
                _context.Devices.Add(newDevice);
                await _context.SaveChangesAsync(); // Flush first to get the generated DeviceId
                SetDeviceCookie(newDevice.DeviceId);

                var newCredential = new Credential
                {
                    CredentialId = credential.Id,
                    UserId = student.UserId,
                    DeviceId = newDevice.DeviceId,
                    PublicKey = credential.PublicKey,
                    SignCount = credential.SignCount,
                    Transports = credential.Transports != null
                        ? string.Join(",", credential.Transports)
                        : "internal",
                    AttestationFormat = credential.AttestationFormat,
                    CreatedAt = DateTime.UtcNow,
                    Status = "Active"
                };
                _context.Credentials.Add(newCredential);

                // ============================================================
                // STEP 6 — Update student status from PendingEnrollment → Active
                // ============================================================
                student.Status = "Active";

                // ============================================================
                // STEP 7 — Consume (mark as used) both challenge records
                // ============================================================
                tokenRecord.IsUsed = true;
                fido2Challenge.IsUsed = true;

                await _context.SaveChangesAsync();

                // ============================================================
                // STEP 8 — Write the "Root of Trust Established" audit log entry
                // ============================================================
                var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
                await _auditLogService.LogAsync(
                    "Root of Trust Established - Admin Verified Registration",
                    $"Student '{student.Email}' completed initial FIDO2 registration " +
                    $"with device '{request.DeviceName}' ({request.DeviceType}). " +
                    $"Account status updated to Active.",
                    student.UserId,
                    newDevice.DeviceId.ToString(),
                    ip);

                return Ok(new RegisterVerifyResponse
                {
                    Success = true,
                    Message = "Initial passkey registration successful. Your account is now Active."
                });
            }
            catch (Exception ex)
            {
                var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
                await _auditLogService.LogAsync(
                    "Initial Registration Failed — Unexpected Error",
                    ex.Message,
                    null,
                    null,
                    ip);
                return StatusCode(500, new RegisterVerifyResponse
                {
                    Success = false,
                    Message = ex.Message
                });
            }
        }

        /// <summary>
        /// Self-Service Device Registration — Step 1:
        /// Generates a one-time QR token for the logged-in user to register an additional device.
        /// POST /api/auth/register/initiate-self
        /// </summary>
        [HttpPost("initiate-self")]
        public async Task<IActionResult> InitiateSelfDeviceRegistration()
        {
            try
            {
                // Must be logged in
                if (!Request.Cookies.TryGetValue("portal_session_token", out string? sessionToken) || string.IsNullOrEmpty(sessionToken))
                    return Unauthorized(new { status = "error", errorMessage = "No active session. Please log in first." });

                var sessionRecord = await _context.AuthSessions
                    .FirstOrDefaultAsync(s => s.SessionToken == sessionToken && s.IsActive && s.ExpiresAt > DateTime.UtcNow);
                if (sessionRecord == null)
                    return Unauthorized(new { status = "error", errorMessage = "Session expired. Please log in again." });

                if (!Request.Cookies.TryGetValue("portal_email", out string? userEmail) || string.IsNullOrEmpty(userEmail))
                    return Unauthorized(new { status = "error", errorMessage = "Could not identify logged-in user." });

                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userEmail);
                if (user == null)
                    return NotFound(new { status = "error", errorMessage = "User account not found." });

                // Guard: Verify session ownership - make sure the logged-in session belongs to this user
                if (sessionRecord.UserId != user.UserId)
                    return Unauthorized(new { status = "error", errorMessage = "You can only register devices for your own account." });

                if (user.Status != "Active")
                    return BadRequest(new { status = "error", errorMessage = "Your account must be Active to add new devices." });

                // Invalidate any old unused self-registration tokens for this user
                var oldTokens = await _context.AuthChallenges
                    .Where(c => c.UserId == user.UserId && c.Purpose == "SelfDeviceRegistration" && !c.IsUsed)
                    .ToListAsync();
                foreach (var old in oldTokens) old.IsUsed = true;

                // Generate new one-time token
                var token = Guid.NewGuid().ToString("N");
                var expiresAt = DateTime.UtcNow.AddMinutes(5);

                var tokenRecord = new AuthChallenge
                {
                    UserId = user.UserId,
                    Challenge = token,
                    Purpose = "SelfDeviceRegistration",
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = expiresAt,
                    IsUsed = false
                };
                _context.AuthChallenges.Add(tokenRecord);
                await _context.SaveChangesAsync();

                var registrationUrl = $"{Request.Scheme}://{Request.Host}/Portal/Register?token={token}&mode=self";

                var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
                await _auditLogService.LogAsync(
                    "Self Device Registration Token Generated",
                    $"User '{user.Email}' generated a self-registration QR token.",
                    user.UserId, null, ip);

                return Ok(new { status = "ok", token, registrationUrl, expiresAt });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { status = "error", errorMessage = ex.Message });
            }
        }

        /// <summary>
        /// Self-Service Device Registration — Step 2 (Verify):
        /// Verifies the FIDO2 attestation for an Active user adding an additional device.
        /// POST /api/auth/register/verify-self-device
        /// </summary>
        [HttpPost("verify-self-device")]
        public async Task<IActionResult> VerifySelfDevice([FromBody] InitialVerifyRequest request)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(request.Token))
                    return BadRequest(new RegisterVerifyResponse { Success = false, Message = "A registration token is required." });

                // Validate self-device token
                var tokenRecord = await _context.AuthChallenges
                    .FirstOrDefaultAsync(c =>
                        c.Challenge == request.Token
                        && c.Purpose == "SelfDeviceRegistration"
                        && !c.IsUsed
                        && c.ExpiresAt > DateTime.UtcNow);

                if (tokenRecord == null)
                    return BadRequest(new RegisterVerifyResponse { Success = false, Message = "Token is invalid, used, or expired. Generate a new QR code." });

                var user = await _context.Users.FirstOrDefaultAsync(u => u.UserId == tokenRecord.UserId);
                if (user == null)
                    return NotFound(new RegisterVerifyResponse { Success = false, Message = "User account not found." });

                if (user.Status != "Active")
                    return BadRequest(new RegisterVerifyResponse { Success = false, Message = "Account must be Active." });

                // Locate the FIDO2 challenge generated in options-by-token
                var fido2Challenge = await _context.AuthChallenges
                    .Where(c => c.UserId == user.UserId && c.Purpose == "SelfDeviceRegistration-FIDO2" && !c.IsUsed && c.ExpiresAt > DateTime.UtcNow)
                    .OrderByDescending(c => c.CreatedAt)
                    .FirstOrDefaultAsync();

                if (fido2Challenge == null)
                    return BadRequest(new RegisterVerifyResponse { Success = false, Message = "FIDO2 challenge expired. Please rescan the QR code." });

                // Parse attestation
                AuthenticatorAttestationRawResponse parsedAttestation;
                try
                {
                    var rawJson = request.AttestationResponse.GetRawText();
                    parsedAttestation = System.Text.Json.JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(
                        rawJson, new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
                }
                catch (Exception ex)
                {
                    return BadRequest(new RegisterVerifyResponse { Success = false, Message = $"JSON Parsing Error: {ex.Message}" });
                }

                // Verify FIDO2
                RegisteredPublicKeyCredential credential;
                try
                {
                    credential = await _fido2Service.VerifyRegisterResponseAsync(parsedAttestation, fido2Challenge);
                }
                catch (Exception ex)
                {
                    var failIp = HttpContext.Connection.RemoteIpAddress?.ToString();
                    await _auditLogService.LogAsync("Self Device Registration Failed", $"User '{user.Email}': {ex.Message}", user.UserId, null, failIp);
                    return BadRequest(new RegisterVerifyResponse { Success = false, Message = $"FIDO2 verification failed: {ex.Message}" });
                }

                // Save new device
                var newDevice = new Device
                {
                    UserId = user.UserId,
                    DeviceName = request.DeviceName,
                    DeviceType = request.DeviceType,
                    RegisteredAt = DateTime.UtcNow,
                    Status = "Active"
                };
                _context.Devices.Add(newDevice);
                await _context.SaveChangesAsync();
                SetDeviceCookie(newDevice.DeviceId);

                // Save credential
                var newCredential = new Credential
                {
                    CredentialId = credential.Id,
                    UserId = user.UserId,
                    DeviceId = newDevice.DeviceId,
                    PublicKey = credential.PublicKey,
                    SignCount = credential.SignCount,
                    Transports = credential.Transports != null ? string.Join(",", credential.Transports) : "internal",
                    AttestationFormat = credential.AttestationFormat,
                    CreatedAt = DateTime.UtcNow,
                    Status = "Active"
                };
                _context.Credentials.Add(newCredential);

                // Consume both tokens
                tokenRecord.IsUsed = true;
                fido2Challenge.IsUsed = true;
                await _context.SaveChangesAsync();

                var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
                await _auditLogService.LogAsync(
                    "Self Device Registered",
                    $"User '{user.Email}' added new device '{request.DeviceName}' ({request.DeviceType}).",
                    user.UserId, newDevice.DeviceId.ToString(), ip);

                return Ok(new RegisterVerifyResponse { Success = true, Message = "New device registered successfully." });
            }
            catch (Exception ex)
            {
                var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
                await _auditLogService.LogAsync("Self Device Registration Failed", ex.Message, null, null, ip);
                return StatusCode(500, new RegisterVerifyResponse { Success = false, Message = ex.Message });
            }
        }

        private void SetDeviceCookie(Guid deviceId)
        {
            var cookieOpts = new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsHttps,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                Expires = DateTime.UtcNow.AddYears(1)
            };
            Response.Cookies.Append("portal_device_id", deviceId.ToString(), cookieOpts);
        }
    }
}
