using System;
using System.Linq;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Objects;
using NexusUniversityWebPortal.AuthBackend.Data;
using NexusUniversityWebPortal.AuthBackend.Models;
using NexusUniversityWebPortal.AuthBackend.Services;
using NexusUniversityWebPortal.AuthBackend.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace NexusUniversityWebPortal.AuthBackend.Controllers
{
    [ApiController]
    [Route("api/auth/login")]
    public class LoginController : ControllerBase
    {
        private readonly Fido2Service _fido2Service;
        private readonly AuditLogService _auditLogService;
        private readonly ApplicationDbContext _context;

        public LoginController(
            Fido2Service fido2Service,
            AuditLogService auditLogService,
            ApplicationDbContext context)
        {
            _fido2Service = fido2Service;
            _auditLogService = auditLogService;
            _context = context;
        }


        [HttpPost("options")]
        public async Task<IActionResult> GenerateOptions([FromBody] LoginOptionsRequest request)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email || u.StudentStaffId == request.Email);
                var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
                if (user == null)
                {
                    await _auditLogService.LogAsync("Login Failed", $"User not found: {request.Email}", null, null, ip);
                    return NotFound(new LoginOptionsResponse { Status = "error", ErrorMessage = "User not found" });
                }

#if DEBUG
                if (user.Email == "superadmin@university.edu")
                {
                    var devChallenge = new AuthChallenge
                    {
                        UserId = user.UserId,
                        Challenge = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                        Purpose = "Login",
                        CreatedAt = DateTime.UtcNow,
                        ExpiresAt = DateTime.UtcNow.AddMinutes(5),
                        IsUsed = false
                    };
                    _context.AuthChallenges.Add(devChallenge);
                    await _context.SaveChangesAsync();

                    return Ok(new LoginOptionsResponse { Status = "ok", Options = null });
                }
#endif

                if (user.Status != "Active")
                {
                    await _auditLogService.LogAsync("Login Failed", "User account is not active", user.UserId, null, ip);
                    return BadRequest(new LoginOptionsResponse { Status = "error", ErrorMessage = "User account is not active. Please complete registration first." });
                }



                var existingCredentials = await _context.Credentials
                    .Where(c => c.UserId == user.UserId && c.Status == "Active")
                    .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
                    .ToListAsync();

                if (!existingCredentials.Any())
                {
                    await _auditLogService.LogAsync("Login Failed", "No active passkeys found", user.UserId, null, ip);
                    return BadRequest(new LoginOptionsResponse { Status = "error", ErrorMessage = "No active passkeys found for this user." });
                }

                var options = await _fido2Service.GenerateLoginOptionsAsync(user, existingCredentials);

                await _auditLogService.LogAsync("Login Options Generated", $"For user {user.Email}", user.UserId, null, ip);

                return Ok(new LoginOptionsResponse { Status = "ok", Options = options });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new LoginOptionsResponse { Status = "error", ErrorMessage = ex.Message });
            }
        }

        [HttpPost("options-cda")]
        public async Task<IActionResult> GenerateCdaOptions([FromBody] LoginOptionsRequest request)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email || u.StudentStaffId == request.Email);
                var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
                if (user == null)
                {
                    await _auditLogService.LogAsync("Login Failed", $"User not found: {request.Email}", null, null, ip);
                    return NotFound(new LoginOptionsResponse { Status = "error", ErrorMessage = "User not found" });
                }

                if (user.Status != "Active")
                {
                    await _auditLogService.LogAsync("Login Failed", "User account is not active", user.UserId, null, ip);
                    return BadRequest(new LoginOptionsResponse { Status = "error", ErrorMessage = "User account is not active." });
                }

                var existingCredentials = await _context.Credentials
                    .Include(c => c.Device)
                    .Where(c => c.UserId == user.UserId && c.Status == "Active" && c.Device != null && (c.Device.Status == "Active" || c.Device.Status == "Approved"))
                    .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
                    .ToListAsync();

                if (!existingCredentials.Any())
                {
                    await _auditLogService.LogAsync("Login Failed", "No active passkeys found", user.UserId, null, ip);
                    return BadRequest(new LoginOptionsResponse { Status = "error", ErrorMessage = "No active passkeys found for this user." });
                }

                var options = await _fido2Service.GenerateLoginOptionsForCdaAsync(user, existingCredentials);

                await _auditLogService.LogAsync("CDA Login Options Generated", $"For user {user.Email}", user.UserId, null, ip);

                return Ok(new LoginOptionsResponse { Status = "ok", Options = options });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new LoginOptionsResponse { Status = "error", ErrorMessage = ex.Message });
            }
        }

        [HttpPost("verify")]
        public async Task<IActionResult> VerifyResponse([FromBody] LoginVerifyRequest request)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email || u.StudentStaffId == request.Email);
                var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
                if (user == null)
                {
                    await _auditLogService.LogAsync("Login Failed", $"User not found: {request.Email}", null, null, ip);
                    return NotFound(new LoginVerifyResponse { Success = false, Message = "User not found" });
                }

#if DEBUG
                if (user.Email == "superadmin@university.edu")
                {
                    var devSessionToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
                    var devIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
                    var devUserAgent = Request.Headers["User-Agent"].ToString();

                    var devSession = new AuthSession
                    {
                        UserId = user.UserId,
                        DeviceId = null,
                        SessionToken = devSessionToken,
                        IpAddress = devIp,
                        UserAgent = devUserAgent,
                        CreatedAt = DateTime.UtcNow,
                        ExpiresAt = DateTime.UtcNow.AddMinutes(5),
                        IsActive = true
                    };

                    // Mark all active login challenges for this user as used
                    var challenges = await _context.AuthChallenges
                        .Where(c => c.UserId == user.UserId && c.Purpose == "Login" && !c.IsUsed)
                        .ToListAsync();
                    foreach (var c in challenges)
                    {
                        c.IsUsed = true;
                    }

                    _context.AuthSessions.Add(devSession);
                    await _context.SaveChangesAsync();

                    var devCookieOpts = new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = Request.IsHttps,
                        SameSite = SameSiteMode.Strict,
                        Path = "/", // Scope dev bypass cookies explicitly to root
                        Expires = devSession.ExpiresAt
                    };

                    Response.Cookies.Append("portal_role", user.RoleId ?? "admin", devCookieOpts);
                    Response.Cookies.Append("portal_email", user.Email, devCookieOpts);
                    Response.Cookies.Append("portal_name", string.IsNullOrWhiteSpace(user.FullName) ? user.Email : user.FullName, devCookieOpts);
                    Response.Cookies.Append("portal_id", user.StudentStaffId, devCookieOpts);
                    Response.Cookies.Append("portal_last_active", DateTime.UtcNow.ToString("O"), devCookieOpts);
                    Response.Cookies.Append("portal_session_token", devSessionToken, devCookieOpts);

                    await _auditLogService.LogAsync("Login Success (Dev Bypass)", "User logged in via local development bypass", user.UserId, null, devIp);

                    return Ok(new LoginVerifyResponse { Success = true, Message = "Local development bypass successful" });
                }
#endif

                var challenge = await _context.AuthChallenges
                    .Where(c => c.UserId == user.UserId && !c.IsUsed && c.Purpose == "Login" && c.ExpiresAt > DateTime.UtcNow)
                    .OrderByDescending(c => c.CreatedAt)
                    .FirstOrDefaultAsync();

                if (challenge == null)
                {
                    await _auditLogService.LogAsync("Login Failed", "Challenge expired or not found", user.UserId, null, ip);
                    return BadRequest(new LoginVerifyResponse { Success = false, Message = "Challenge expired or not found" });
                }

                byte[] credentialId;
                try
                {
                    var idString = request.AssertionResponse.GetProperty("id").GetString();
                    if (string.IsNullOrWhiteSpace(idString))
                    {
                        await _auditLogService.LogAsync("Login Failed", "Invalid assertion response format", user.UserId, null, ip);
                        return BadRequest(new LoginVerifyResponse { Success = false, Message = "Invalid assertion response format" });
                    }

                    credentialId = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(idString);
                }
                catch (Exception ex)
                {
                    await _auditLogService.LogAsync("Login Failed", $"Invalid assertion format: {ex.Message}", user.UserId, null, ip);
                    return BadRequest(new LoginVerifyResponse { Success = false, Message = "Invalid assertion response format" });
                }

                var credential = await _context.Credentials.FirstOrDefaultAsync(c => c.CredentialId == credentialId && c.UserId == user.UserId && c.Status == "Active");
                if (credential == null)
                {
                    await _auditLogService.LogAsync("Login Failed", "Credential not found or not active", user.UserId, null, ip);
                    return BadRequest(new LoginVerifyResponse { Success = false, Message = "Credential not found or not active" });
                }

                VerifyAssertionResult verifyResult;
                try
                {
                    var rawJson = request.AssertionResponse.GetRawText();
                    var parsedAssertion = System.Text.Json.JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(
                        rawJson,
                        new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
                        
                    verifyResult = await _fido2Service.VerifyLoginResponseAsync(parsedAssertion, challenge, credential.PublicKey, credential.SignCount);
                }
                catch (Exception ex)
                {
                    var failIp = HttpContext.Connection.RemoteIpAddress?.ToString();
                    await _auditLogService.LogAsync("Login Failed", ex.Message, user.UserId, credential.DeviceId.ToString(), failIp);
                    return BadRequest(new LoginVerifyResponse { Success = false, Message = ex.Message });
                }

                // Verify SignCount
                if (verifyResult.SignCount > 0 && verifyResult.SignCount <= credential.SignCount)
                {
                    var failIp = HttpContext.Connection.RemoteIpAddress?.ToString();
                    await _auditLogService.LogAsync("Login Failed - Potential Replay Attack", $"SignCount {verifyResult.SignCount} is not greater than stored {credential.SignCount}", user.UserId, credential.DeviceId.ToString(), failIp);
                    return BadRequest(new LoginVerifyResponse { Success = false, Message = "Potential replay attack detected. SignCount invalid." });
                }

                // Update DB
                credential.SignCount = verifyResult.SignCount;
                credential.LastUsedAt = DateTime.UtcNow;
                
                var device = await _context.Devices.FirstOrDefaultAsync(d => d.DeviceId == credential.DeviceId);
                if (device != null)
                {
                    device.LastUsedAt = DateTime.UtcNow;
                }

                challenge.IsUsed = true;

                // Create AuthSession
                var sessionToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
                ip = ip ?? "127.0.0.1";
                var userAgent = Request.Headers["User-Agent"].ToString();

                var session = new AuthSession
                {
                    UserId = user.UserId,
                    DeviceId = credential.DeviceId,
                    SessionToken = sessionToken,
                    IpAddress = ip,
                    UserAgent = userAgent,
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(5),
                    IsActive = true
                };

                _context.AuthSessions.Add(session);
                await _context.SaveChangesAsync();

                // Set secure cookies
                var cookieOpts = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = Request.IsHttps,
                    SameSite = SameSiteMode.Strict,
                    Path = "/", // Scope session cookies explicitly to root so other controllers can delete them properly
                    Expires = session.ExpiresAt
                };

                Response.Cookies.Append("portal_role", user.RoleId ?? "student", cookieOpts);
                Response.Cookies.Append("portal_email", user.Email, cookieOpts);
                Response.Cookies.Append("portal_name", string.IsNullOrWhiteSpace(user.FullName) ? user.Email : user.FullName, cookieOpts);
                Response.Cookies.Append("portal_id", user.StudentStaffId, cookieOpts);
                Response.Cookies.Append("portal_last_active", DateTime.UtcNow.ToString("O"), cookieOpts);
                Response.Cookies.Append("portal_session_token", sessionToken, cookieOpts);

                await _auditLogService.LogAsync("Login Success", "User logged in via FIDO2", user.UserId, credential.DeviceId.ToString(), ip);

                return Ok(new LoginVerifyResponse { Success = true, Message = "Login successful" });
            }
            catch (Exception ex)
            {
                var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
                await _auditLogService.LogAsync("Login Failed", ex.Message, null, null, ip);
                return StatusCode(500, new LoginVerifyResponse { Success = false, Message = ex.Message });
            }
        }

        [HttpPost("report-failure")]
        public async Task<IActionResult> ReportFailure([FromBody] LoginFailureRequest request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email || u.StudentStaffId == request.Email);
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
            
            await _auditLogService.LogAsync("Request Cancelled", $"Client error: {request.ErrorMessage}", user?.UserId, null, ip);
            return Ok();
        }
    }
}
