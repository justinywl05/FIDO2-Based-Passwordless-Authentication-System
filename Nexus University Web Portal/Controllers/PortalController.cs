using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using NexusUniversityWebPortal.AuthBackend.Models;
using Microsoft.AspNetCore.Http;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;

namespace NexusUniversityWebPortal.Controllers
{
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public class PortalController : Controller
    {
        private readonly NexusUniversityWebPortal.AuthBackend.Data.ApplicationDbContext _context;

        public PortalController(NexusUniversityWebPortal.AuthBackend.Data.ApplicationDbContext context)
        {
            _context = context;
        }

        public class Role
        {
            public string RoleId { get; set; } = string.Empty;
            public string RoleName { get; set; } = string.Empty;
            public string Description { get; set; } = string.Empty;
            public List<string> Permissions { get; set; } = new();
        }

        // Keep Roles mapping for RBAC
        public static readonly List<Role> Roles = new()
        {
            new Role 
            { 
                RoleId = "student", 
                RoleName = "Student", 
                Description = "University Student Access",
                Permissions = new List<string> { "read:dashboard", "read:profile", "write:profile", "VIEW_MATERIAL" }
            },
            new Role 
            { 
                RoleId = "lecturer", 
                RoleName = "Lecturer", 
                Description = "Academic Staff Access",
                Permissions = new List<string> { "read:dashboard", "read:profile", "write:profile", "grade:students", "attendance:manage", "VIEW_MATERIAL", "UPLOAD_MATERIAL", "UPDATE_MATERIAL" }
            },
            new Role 
            { 
                RoleId = "admin", 
                RoleName = "Admin", 
                Description = "System Administrator Access",
                Permissions = new List<string> { "read:dashboard", "read:profile", "write:profile", "manage:devices", "manage:sessions", "read:logs", "manage:users", "manage:roles", "VIEW_MATERIAL", "UPLOAD_MATERIAL", "UPDATE_MATERIAL", "DELETE_MATERIAL" }
            }
        };

        public class LoginRequest
        {
            public string Username { get; set; } = string.Empty;
        }

        private static string GenerateSessionToken()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        private CookieOptions BuildSecurityCookieOptions(DateTime? expires = null)
        {
            return new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsHttps,
                SameSite = SameSiteMode.Strict,
                Path = "/", // Explicitly scope cookies to root path for consistent cross-controller deletion
                Expires = expires
            };
        }

        // Validate active session token, user association, and sliding timeout
        private bool ValidateSession()
        {
            // 1. Retrieve the session token from secure cookie
            if (!Request.Cookies.TryGetValue("portal_session_token", out string? sessionToken) || string.IsNullOrEmpty(sessionToken))
            {
                return true; // Session is invalid/expired (trigger redirect)
            }

            // 2. Look up the session record in the database
            var session = _context.AuthSessions.FirstOrDefault(s => s.SessionToken == sessionToken);
            if (session == null || !session.IsActive)
            {
                return true; // Session is invalid
            }

            // 3. Verify session matches the authenticated user in the cookies
            if (Request.Cookies.TryGetValue("portal_email", out string? cookieEmail))
            {
                var user = _context.Users.FirstOrDefault(u => u.Email == cookieEmail);
                if (user == null || session.UserId != user.UserId)
                {
                    session.IsActive = false;
                    _context.SaveChanges();
                    return true; // Session doesn't match the current user!
                }
            }
            else
            {
                return true; // No authenticated user cookie found
            }

            // 4. Verify sliding inactivity expiration (5 minutes)
            if (Request.Cookies.TryGetValue("portal_last_active", out string? lastActiveStr))
            {
                if (DateTime.TryParse(lastActiveStr, out DateTime lastActive))
                {
                    if ((DateTime.UtcNow - lastActive.ToUniversalTime()).TotalMinutes > 5)
                    {
                        session.IsActive = false;
                        _context.SaveChanges();
                        return true; // Session expired
                    }
                }
            }

            // Verify absolute expiration of the session record
            if (session.ExpiresAt < DateTime.UtcNow)
            {
                session.IsActive = false;
                _context.SaveChanges();
                return true; // Session expired absolutely
            }

            // 5. Slide expiration forward in both cookie and database
            session.ExpiresAt = DateTime.UtcNow.AddMinutes(5);

            Response.Cookies.Append("portal_last_active", DateTime.UtcNow.ToString("O"), BuildSecurityCookieOptions());
            _context.SaveChanges();
            
            return false; // Session is valid and active
        }

        private bool CheckSessionInactivity()
        {
            return ValidateSession();
        }

        private List<Role> GetRolesForDisplay()
        {
            return Roles.ToList();
        }

        private bool RoleExists(string roleId)
        {
            return Roles.Any(r => r.RoleId == roleId);
        }

        private List<string> GetRolePermissions(string roleId)
        {
            return Roles.FirstOrDefault(r => r.RoleId == roleId)?.Permissions ?? new List<string>();
        }

        // Validate if logged-in role has specific permission
        private bool HasPermission(string permission)
        {
            var user = GetAuthenticatedUser();
            return user != null && GetRolePermissions(user.RoleId).Contains(permission);
        }

        private User? GetAuthenticatedUser()
        {
            if (!Request.Cookies.TryGetValue("portal_session_token", out string? sessionToken) || string.IsNullOrEmpty(sessionToken))
            {
                return null;
            }

            var session = _context.AuthSessions.FirstOrDefault(s => s.SessionToken == sessionToken && s.IsActive);
            if (session == null || session.ExpiresAt < DateTime.UtcNow)
            {
                return null;
            }

            if (!Request.Cookies.TryGetValue("portal_email", out string? email) || string.IsNullOrEmpty(email))
            {
                return null;
            }

            var emailLower = email.ToLower();
            var user = _context.Users.FirstOrDefault(u => u.Email.ToLower() == emailLower);
            if (user == null || session.UserId != user.UserId)
            {
                return null;
            }

            return user;
        }

        private string GetClientIp()
        {
            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
        }

        private Device ResolveSessionDevice(User user)
        {
            var device = _context.Devices.FirstOrDefault(d =>
                d.UserId == user.UserId &&
                (d.Status == "Approved" || d.Status == "Active"))
                ?? _context.Devices.FirstOrDefault(d => d.UserId == user.UserId);

            if (device != null)
            {
                return device;
            }

            device = new Device
            {
                DeviceId = Guid.NewGuid(),
                UserId = user.UserId,
                DeviceName = "FIDO2 Authenticator",
                DeviceType = "Passkey",
                RegisteredAt = DateTime.Now,
                Status = "Active"
            };

            _context.Devices.Add(device);
            return device;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Login(bool? expired)
        {
            if (expired == true)
            {
                ViewBag.ExpiredMessage = "Your session expired due to 5 minutes of inactivity. Please re-authenticate.";
            }

            var user = GetAuthenticatedUser();
            if (user != null)
            {
                return RedirectToAction("Dashboard", new { role = user.RoleId });
            }
            else
            {
                // Clean-up guard: If the user is on the login page but holds an invalid, revoked, or expired session token cookie,
                // proactively delete all security cookies from the browser. This prevents stale browser state and cookie reuse.
                if (Request.Cookies.ContainsKey("portal_session_token"))
                {
                    var deleteOptions = BuildSecurityCookieOptions(DateTime.UtcNow.AddDays(-1));
                    Response.Cookies.Delete("portal_role", deleteOptions);
                    Response.Cookies.Delete("portal_email", deleteOptions);
                    Response.Cookies.Delete("portal_name", deleteOptions);
                    Response.Cookies.Delete("portal_id", deleteOptions);
                    Response.Cookies.Delete("portal_last_active", deleteOptions);
                    Response.Cookies.Delete("portal_session_token", deleteOptions);
                }
            }
            return View();
        }

        [HttpPost]
        public IActionResult Login(string email, string? authType)
        {
            return Unauthorized("Passkey verification is required. Use /api/auth/login/options and /api/auth/login/verify.");
        }

        [HttpPost("/api/auth/login")]
        public IActionResult ApiAuthLogin([FromBody] LoginRequest? requestData)
        {
            return Unauthorized(new { success = false, message = "Passkey verification is required." });
        }

        public IActionResult Logout(bool? expired)
        {
            var user = GetAuthenticatedUser();

            // 1. Invalidate the session record in the database immediately.
            // This ensures that the session token is marked inactive and cannot be re-used,
            // addressing the cookie reuse security concern.
            if (Request.Cookies.TryGetValue("portal_session_token", out string? sessionToken) && !string.IsNullOrEmpty(sessionToken))
            {
                var session = _context.AuthSessions.FirstOrDefault(s => s.SessionToken == sessionToken);
                if (session != null)
                {
                    session.IsActive = false;
                    session.RevokedAt = DateTime.UtcNow; // Record revocation timestamp for audit trail
                }
            }

            // 2. Log the logout action for security compliance and audit logging.
            if (user != null)
            {
                var log = new AuditLog
                {
                    UserId = user.UserId,
                    Action = expired == true ? "Session Expired" : "Logout",
                    Details = expired == true ? $"User session terminated automatically due to 5 mins inactivity." : $"User {user.FullName} logged out manually.",
                    IpAddress = GetClientIp(),
                    CreatedAt = DateTime.UtcNow
                };
                _context.AuditLogs.Add(log);
            }

            // 3. PERSIST CHANGES TO DATABASE.
            // Critical fix: Ensure changes to both the deactivated session and the audit log are saved.
            _context.SaveChanges();

            // 4. Force browser to delete security cookies.
            // Using strict delete options ensures compliance across modern security-conscious browsers.
            var deleteOptions = BuildSecurityCookieOptions(DateTime.UtcNow.AddDays(-1));
            Response.Cookies.Delete("portal_role", deleteOptions);
            Response.Cookies.Delete("portal_email", deleteOptions);
            Response.Cookies.Delete("portal_name", deleteOptions);
            Response.Cookies.Delete("portal_id", deleteOptions);
            Response.Cookies.Delete("portal_last_active", deleteOptions);
            Response.Cookies.Delete("portal_session_token", deleteOptions);

            return RedirectToAction("Login", new { expired = expired });
        }

        [HttpPost]
        public IActionResult ActionRefreshSession()
        {
            if (CheckSessionInactivity())
            {
                return Json(new { success = false, message = "session_expired" });
            }

            var user = GetAuthenticatedUser();
            if (user == null)
            {
                return Json(new { success = false, message = "session_invalid" });
            }

            return Json(new { success = true, expiresInSeconds = 300, user = user.FullName });
        }

        public IActionResult Dashboard(string? role)
        {
            if (CheckSessionInactivity()) return RedirectToAction("Logout", new { expired = true });

            var currentUser = GetAuthenticatedUser();
            if (currentUser == null)
            {
                return RedirectToAction("Login");
            }

            // Access control policy check
            if (!HasPermission("read:dashboard"))
            {
                return RedirectToAction("UnauthorizedPage", new { requiredPermission = "read:dashboard" });
            }

            SetLayoutViewBag(currentUser.RoleId);
            
            // Load binded devices for the current user
            ViewBag.UserDevices = _context.Devices.Where(d => d.UserId == currentUser.UserId).ToList();

            return View();
        }

        public IActionResult Profile()
        {
            if (CheckSessionInactivity()) return RedirectToAction("Logout", new { expired = true });

            var currentUser = GetAuthenticatedUser();
            if (currentUser == null)
            {
                return RedirectToAction("Login");
            }

            if (!HasPermission("read:profile"))
            {
                return RedirectToAction("UnauthorizedPage", new { requiredPermission = "read:profile" });
            }

            SetLayoutViewBag(currentUser.RoleId);
            
            // Get credentials list belonging to logged-in user
            ViewBag.UserCredentials = _context.Credentials.Where(c => c.UserId == currentUser.UserId).ToList();
            ViewBag.UserDevices = _context.Devices.Where(d => d.UserId == currentUser.UserId).ToList();
            ViewBag.UserSessions = _context.AuthSessions
                .Where(s => s.UserId == currentUser.UserId && s.IsActive && s.ExpiresAt > DateTime.UtcNow)
                .OrderByDescending(s => s.CreatedAt).ToList();

            return View();
        }

        public IActionResult MyDevices()
        {
            if (CheckSessionInactivity()) return RedirectToAction("Logout", new { expired = true });

            var currentUser = GetAuthenticatedUser();
            if (currentUser == null) return RedirectToAction("Login");

            if (currentUser.RoleId == "admin")
                return RedirectToAction("AdminDevices");

            SetLayoutViewBag(currentUser.RoleId);

            // Oldest device = admin-enrolled root-of-trust, mark it protected
            var devices = _context.Devices
                .Where(d => d.UserId == currentUser.UserId)
                .OrderBy(d => d.RegisteredAt)
                .ToList();

            var oldestDeviceId = devices.FirstOrDefault()?.DeviceId;
            ViewBag.ProtectedDeviceId = oldestDeviceId;
            return View(devices);
        }

        public IActionResult MySessions()
        {
            if (CheckSessionInactivity()) return RedirectToAction("Logout", new { expired = true });

            var currentUser = GetAuthenticatedUser();
            if (currentUser == null) return RedirectToAction("Login");

            if (currentUser.RoleId == "admin")
                return RedirectToAction("AdminSessions");

            SetLayoutViewBag(currentUser.RoleId);

            var sessions = _context.AuthSessions
                .Where(s => s.UserId == currentUser.UserId && s.IsActive && s.ExpiresAt > DateTime.UtcNow)
                .Include(s => s.Device)
                .OrderByDescending(s => s.CreatedAt)
                .ToList();

            return View(sessions);
        }

        [HttpPost]
        public IActionResult ActionRevokeOwnDevice(Guid deviceId)
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });

            var currentUser = GetAuthenticatedUser();
            if (currentUser == null) return Json(new { success = false, message = "unauthorized" });

            // Verify the device belongs to the current user
            var dev = _context.Devices.FirstOrDefault(d => d.DeviceId == deviceId && d.UserId == currentUser.UserId);
            if (dev == null) return Json(new { success = false, message = "Device not found or does not belong to your account." });

            // Protect the oldest (admin-registered root-of-trust) device
            var oldestDevice = _context.Devices
                .Where(d => d.UserId == currentUser.UserId)
                .OrderBy(d => d.RegisteredAt)
                .FirstOrDefault();
            if (oldestDevice != null && oldestDevice.DeviceId == deviceId)
                return Json(new { success = false, message = "Your primary enrolled device is protected and cannot be removed. Contact your administrator." });

            // Ensure the user retains at least one active credential after removal
            var credCount = _context.Credentials.Count(c => c.UserId == currentUser.UserId && c.Status == "Active");
            var credsOnDevice = _context.Credentials.Count(c => c.DeviceId == deviceId && c.Status == "Active");
            if (credCount - credsOnDevice < 1)
                return Json(new { success = false, message = "You must keep at least one active passkey on your account." });

            // Remove credentials on this device
            var creds = _context.Credentials.Where(c => c.DeviceId == deviceId).ToList();
            _context.Credentials.RemoveRange(creds);

            // Terminate sessions from this device
            var sessions = _context.AuthSessions.Where(s => s.DeviceId == deviceId && s.IsActive).ToList();
            foreach (var s in sessions) { s.IsActive = false; s.RevokedAt = DateTime.UtcNow; }

            _context.Devices.Remove(dev);

            var log = new AuditLog
            {
                UserId = currentUser.UserId,
                DeviceId = deviceId.ToString(),
                Action = "Self-Service Device Removed",
                Details = $"User {currentUser.FullName} removed their own device '{dev.DeviceName}'.",
                IpAddress = GetClientIp(),
                CreatedAt = DateTime.UtcNow
            };
            _context.AuditLogs.Add(log);
            _context.SaveChanges();

            return Json(new { success = true });
        }

        [HttpPost]
        public IActionResult ActionTerminateOwnSession(Guid sessionId)
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });

            var currentUser = GetAuthenticatedUser();
            if (currentUser == null) return Json(new { success = false, message = "unauthorized" });

            // Verify the session belongs to the current user and is not the current session
            Request.Cookies.TryGetValue("portal_session_token", out string? currentToken);
            var ses = _context.AuthSessions.FirstOrDefault(s => s.AuthSessionId == sessionId && s.UserId == currentUser.UserId);
            if (ses == null) return Json(new { success = false, message = "Session not found or does not belong to your account." });
            if (ses.SessionToken == currentToken) return Json(new { success = false, message = "You cannot terminate your current session here. Use Logout instead." });

            ses.IsActive = false;
            ses.RevokedAt = DateTime.UtcNow;

            var log = new AuditLog
            {
                UserId = currentUser.UserId,
                Action = "Self-Service Session Terminated",
                Details = $"User {currentUser.FullName} terminated their own session from IP {ses.IpAddress}.",
                IpAddress = GetClientIp(),
                CreatedAt = DateTime.UtcNow
            };
            _context.AuditLogs.Add(log);
            _context.SaveChanges();

            return Json(new { success = true });
        }

        [HttpPost]
        public IActionResult ActionTerminateAllOwnOther()
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });

            var currentUser = GetAuthenticatedUser();
            if (currentUser == null) return Json(new { success = false, message = "unauthorized" });

            Request.Cookies.TryGetValue("portal_session_token", out string? currentToken);

            // Fetch only non-expired other active sessions.
            // Fix: Adding s.ExpiresAt > DateTime.UtcNow guarantees we only target and count sessions
            // that are genuinely active, resolving the issue where it reports terminating expired zombie sessions
            // that aren't even visible in the UI sessions list.
            var others = _context.AuthSessions
                .Where(s => s.UserId == currentUser.UserId && s.IsActive && s.ExpiresAt > DateTime.UtcNow && s.SessionToken != currentToken)
                .ToList();

            foreach (var s in others) 
            { 
                s.IsActive = false; 
                s.RevokedAt = DateTime.UtcNow; 
            }

            var log = new AuditLog
            {
                UserId = currentUser.UserId,
                Action = "Self-Service All Other Sessions Terminated",
                Details = $"User {currentUser.FullName} signed out all other sessions ({others.Count} terminated).",
                IpAddress = GetClientIp(),
                CreatedAt = DateTime.UtcNow
            };
            _context.AuditLogs.Add(log);
            _context.SaveChanges();

            return Json(new { success = true, count = others.Count });
        }


        public IActionResult AdminDevices()
        {
            if (CheckSessionInactivity()) return RedirectToAction("Logout", new { expired = true });

            if (!HasPermission("manage:devices"))
            {
                return RedirectToAction("UnauthorizedPage", new { requiredPermission = "manage:devices" });
            }

            SetLayoutViewBag("admin");
            ViewBag.Users = _context.Users.OrderBy(u => u.FullName).ToList();
            return View(_context.Devices.Include(d => d.User).ToList());
        }

        public IActionResult AdminSessions()
        {
            if (CheckSessionInactivity()) return RedirectToAction("Logout", new { expired = true });

            if (!HasPermission("manage:sessions"))
            {
                return RedirectToAction("UnauthorizedPage", new { requiredPermission = "manage:sessions" });
            }

            SetLayoutViewBag("admin");
            var sessions = _context.AuthSessions
                .Where(s => s.IsActive && s.ExpiresAt > DateTime.UtcNow)
                .Include(s => s.Device)
                    .ThenInclude(d => d != null ? d.User : null)
                .Include(s => s.User)
                .OrderByDescending(s => s.CreatedAt)
                .ToList();

            return View(sessions);
        }

        public IActionResult SecurityDashboard()
        {
            if (CheckSessionInactivity()) return RedirectToAction("Logout", new { expired = true });

            if (!HasPermission("read:logs"))
                return RedirectToAction("UnauthorizedPage", new { requiredPermission = "read:logs" });

            SetLayoutViewBag("admin");
            return View();
        }

        public IActionResult SecurityAnalytics()
        {
            if (CheckSessionInactivity()) return RedirectToAction("Logout", new { expired = true });

            if (!HasPermission("read:logs"))
                return RedirectToAction("UnauthorizedPage", new { requiredPermission = "read:logs" });

            SetLayoutViewBag("admin");

            var allLogs = _context.AuditLogs.ToList();
            var loginAttempts = allLogs.Where(l => l.Action.Contains("Login")).ToList();
            var successLogins = loginAttempts.Where(l => l.Action.Contains("Success")).Count();
            var failedLogins  = loginAttempts.Where(l => l.Action.Contains("Failed")).Count();
            var totalLogins   = successLogins + failedLogins;
            var activeSessions = _context.AuthSessions.Count(s => s.IsActive && s.ExpiresAt > DateTime.UtcNow);
            var securityScore = totalLogins == 0 ? 100 : Math.Max(0, 100 - (int)Math.Round((double)failedLogins / totalLogins * 100));

            ViewBag.TotalLogins    = totalLogins;
            ViewBag.SuccessLogins  = successLogins;
            ViewBag.FailedLogins   = failedLogins;
            ViewBag.ActiveSessions = activeSessions;
            ViewBag.SecurityScore  = securityScore;
            ViewBag.TotalDevices   = _context.Devices.Count();

            return View();
        }

        [HttpGet]
        public IActionResult GetSecurityStats()
        {
            if (CheckSessionInactivity()) return Json(new { success = false });
            if (!HasPermission("read:logs")) return Json(new { success = false });

            var now = DateTime.UtcNow.AddHours(8);
            var todayStart = now.Date;
            var todayStartUtc = todayStart.AddHours(-8);

            // --- Hourly trend for today ---
            var todayLogs = _context.AuditLogs
                .Where(l => l.CreatedAt >= todayStartUtc && l.Action.Contains("Login"))
                .ToList();

            var hourlySuccess = new int[24];
            var hourlyFailed  = new int[24];
            foreach (var l in todayLogs)
            {
                var localTime = l.CreatedAt.AddHours(8);
                if (localTime.Date == todayStart)
                {
                    int h = localTime.Hour;
                    if (l.Action.Contains("Success")) hourlySuccess[h]++;
                    else if (l.Action.Contains("Failed")) hourlyFailed[h]++;
                }
            }

            // --- Daily trend for past 7 days ---
            var weekStart = todayStart.AddDays(-6);
            var weekStartUtc = weekStart.AddHours(-8);
            var weekLogs = _context.AuditLogs
                .Where(l => l.CreatedAt >= weekStartUtc && l.Action.Contains("Login"))
                .ToList();

            var dailyLabels  = new string[7];
            var dailySuccess = new int[7];
            var dailyFailed  = new int[7];
            for (int i = 0; i < 7; i++)
            {
                var day = weekStart.AddDays(i);
                dailyLabels[i]  = day.ToString("ddd");
                dailySuccess[i] = weekLogs.Count(l => l.CreatedAt.AddHours(8).Date == day && l.Action.Contains("Success"));
                dailyFailed[i]  = weekLogs.Count(l => l.CreatedAt.AddHours(8).Date == day && l.Action.Contains("Failed"));
            }

            // --- Device distribution ---
            var deviceGroups = _context.Devices
                .GroupBy(d => d.DeviceType ?? "Unknown")
                .Select(g => new { type = g.Key, count = g.Count() })
                .ToList();

            // --- Top 5 active users by login count ---
            var topUsers = _context.AuditLogs
                .Where(l => l.Action.Contains("Login") && l.Action.Contains("Success") && l.UserId != null)
                .GroupBy(l => l.UserId)
                .Select(g => new { userId = g.Key, count = g.Count() })
                .OrderByDescending(g => g.count)
                .Take(5)
                .ToList()
                .Select(g =>
                {
                    var u = _context.Users.FirstOrDefault(u => u.UserId == g.userId);
                    return new
                    {
                        name    = u?.FullName ?? "Unknown",
                        email   = u?.Email ?? "",
                        count   = g.count,
                        lastSeen = _context.AuditLogs
                            .Where(l => l.UserId == g.userId && l.Action.Contains("Login"))
                            .OrderByDescending(l => l.CreatedAt)
                            .Select(l => l.CreatedAt)
                            .FirstOrDefault()
                            .ToString("yyyy-MM-ddTHH:mm:ssZ")
                    };
                })
                .ToList();

            // --- Replay / threat stats from logs ---
            var replayAttempts = _context.AuditLogs.Count(l => l.Action.Contains("Replay"));
            var failedBlocks   = _context.AuditLogs.Count(l => l.Action.Contains("Failed") && !l.Action.Contains("Replay"));

            return Json(new
            {
                success = true,
                hourlySuccess,
                hourlyFailed,
                dailyLabels,
                dailySuccess,
                dailyFailed,
                deviceGroups,
                topUsers,
                replayAttempts,
                blockedAttacks = replayAttempts,
                failedBlocks
            });
        }

        public IActionResult AdminLogs()
        {
            if (CheckSessionInactivity()) return RedirectToAction("Logout", new { expired = true });

            if (!HasPermission("read:logs"))
            {
                return RedirectToAction("UnauthorizedPage", new { requiredPermission = "read:logs" });
            }

            SetLayoutViewBag("admin");
            
            var logs = _context.AuditLogs.OrderByDescending(l => l.CreatedAt).ToList();
            var userIds = logs.Where(l => l.UserId.HasValue).Select(l => l.UserId!.Value).Distinct().ToList();
            var users = _context.Users.Where(u => userIds.Contains(u.UserId)).ToDictionary(u => u.UserId, u => string.IsNullOrEmpty(u.Email) ? u.FullName : u.Email);
            
            foreach(var log in logs)
            {
                if (log.UserId.HasValue && users.TryGetValue(log.UserId.Value, out var email))
                {
                    log.UserEmail = email;
                }
            }
            
            return View(logs);
        }

        public IActionResult AdminUserCreation()
        {
            if (CheckSessionInactivity()) return RedirectToAction("Logout", new { expired = true });

            if (!HasPermission("manage:users"))
            {
                return RedirectToAction("UnauthorizedPage", new { requiredPermission = "manage:users" });
            }

            SetLayoutViewBag("admin");
            return View(_context.Users.ToList());
        }

        public IActionResult AdminRegistration()
        {
            if (CheckSessionInactivity()) return RedirectToAction("Logout", new { expired = true });

            if (!HasPermission("manage:users"))
            {
                return RedirectToAction("UnauthorizedPage", new { requiredPermission = "manage:users" });
            }

            SetLayoutViewBag("admin");
            return View();
        }

        // IAM: User Roles & Permissions assignment
        public IActionResult AdminRoles()
        {
            if (CheckSessionInactivity()) return RedirectToAction("Logout", new { expired = true });

            if (!HasPermission("manage:roles"))
            {
                return RedirectToAction("UnauthorizedPage", new { requiredPermission = "manage:roles" });
            }

            SetLayoutViewBag("admin");
            ViewBag.RolesList = GetRolesForDisplay();
            return View(_context.Users.ToList()); // Pass list of users
        }

        // IAM: 403 Access Denied View
        public IActionResult UnauthorizedPage(string requiredPermission)
        {
            SetLayoutViewBag(GetAuthenticatedUser()?.RoleId ?? "student");
            ViewBag.RequiredPermission = requiredPermission;
            return View();
        }

        // --- POST Endpoints for RBAC mutations ---

        [HttpPost]
        public IActionResult ActionExecutePermission(string actionName)
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });

            // 1. Retrieve the session token from secure cookie
            if (!Request.Cookies.TryGetValue("portal_session_token", out string? sessionToken) || string.IsNullOrEmpty(sessionToken))
            {
                return Json(new { success = false, message = "Authentication failed: No active session token found." });
            }

            // 2. Look up the session record in the database
            var session = _context.AuthSessions.FirstOrDefault(s => s.SessionToken == sessionToken && s.IsActive);
            if (session == null || session.ExpiresAt < DateTime.UtcNow)
            {
                return Json(new { success = false, message = "Session invalid or expired." });
            }

            // 3. Get the user linked to this session
            var user = GetAuthenticatedUser();
            if (user == null || session.UserId != user.UserId)
            {
                return Json(new { success = false, message = "Session mismatch with authenticated user." });
            }

            // 4. Verify user permissions (RBAC)
            var permissions = GetRolePermissions(user.RoleId);
            bool hasAccess = permissions.Contains(actionName);

            // 5. Create audit log entry
            var log = new AuditLog
            {
                UserId = user.UserId,
                DeviceId = session.DeviceId?.ToString(),
                Action = actionName,
                Details = $"{(hasAccess ? "SUCCESS" : "DENIED")} | User {user.FullName} ({user.RoleId}) attempted {actionName}.",
                IpAddress = GetClientIp(),
                CreatedAt = DateTime.UtcNow
            };
            _context.AuditLogs.Add(log);
            _context.SaveChanges();

            if (hasAccess)
            {
                return Json(new { success = true, message = $"Access granted for {actionName}!" });
            }
            else
            {
                return Json(new { success = false, message = $"Access denied for {actionName}!" });
            }
        }

        [HttpPost]
        public IActionResult ActionUpdateUserRole(string userId, string newRoleId)
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });

            if (!HasPermission("manage:roles")) return Json(new { success = false, message = "unauthorized" });
            var actingAdmin = GetAuthenticatedUser();

            if (!Guid.TryParse(userId, out var userGuid)) return Json(new { success = false, message = "Invalid User ID" });

            var userObj = _context.Users.FirstOrDefault(u => u.UserId == userGuid);
            var roleObj = Roles.FirstOrDefault(r => r.RoleId == newRoleId);

            if (userObj != null && roleObj != null)
            {
                var oldRoleId = userObj.RoleId;
                userObj.RoleId = newRoleId;

                // Log the permission alteration
                var log = new AuditLog
                {
                    UserId = userObj.UserId,
                    Action = "Role Configuration Change",
                    Details = $"Admin {actingAdmin?.FullName ?? "Unknown"} changed user {userObj.FullName} role from {oldRoleId} to {newRoleId}.",
                    IpAddress = GetClientIp(),
                    CreatedAt = DateTime.UtcNow
                };
                _context.AuditLogs.Add(log);
                _context.SaveChanges();

                return Json(new { success = true });
            }
            return Json(new { success = false, message = "User or Role not found" });
        }

        [HttpPost]
        public IActionResult ActionUpdateRolePermissions(string roleId, List<string> permissions)
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });

            if (!HasPermission("manage:roles")) return Json(new { success = false, message = "unauthorized" });

            return Json(new { success = false, message = "Static RBAC cannot be modified dynamically." });
        }

        // WebAuthn Passkey Registration simulator
        [HttpPost]
        public IActionResult ActionRegisterPasskey(string descriptorId, string transports, string attestationFormat)
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });

            Request.Cookies.TryGetValue("portal_name", out string? name);
            var user = _context.Users.FirstOrDefault(u => u.FullName == name);
            if (user != null)
            {
                var device = _context.Devices.FirstOrDefault(d => d.UserId == user.UserId) ?? _context.Devices.First();
                
                var passkey = new Credential
                {
                    CredentialId = System.Text.Encoding.UTF8.GetBytes(descriptorId),
                    UserId = user.UserId,
                    DeviceId = device.DeviceId,
                    PublicKey = System.Text.Encoding.UTF8.GetBytes("MIIBojANBgkqhkiG9w0BAQEFAAOCAY8A" + Random.Shared.Next(100000, 999999)),
                    SignCount = 0,
                    Transports = transports,
                    AttestationFormat = attestationFormat,
                    CreatedAt = DateTime.Now,
                    LastUsedAt = DateTime.Now,
                    Status = "Active"
                };
                _context.Credentials.Add(passkey);
                _context.SaveChanges();

                var log = new AuditLog
                {
                    UserId = user.UserId,
                    DeviceId = device.DeviceId.ToString(),
                    Action = "WebAuthn Key Registered",
                    Details = $"Passwordless authentication key ({descriptorId}) registered successfully for device {device.DeviceName}.",
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1",
                    CreatedAt = DateTime.UtcNow
                };
                _context.AuditLogs.Add(log);
                _context.SaveChanges();

                return Json(new { success = true });
            }
            return Json(new { success = false });
        }

        // Clear logs
        [HttpPost]
        public IActionResult ActionClearLogs()
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });
            if (!HasPermission("read:logs")) return Json(new { success = false, message = "unauthorized" });

            _context.AuditLogs.RemoveRange(_context.AuditLogs);
            _context.SaveChanges();
            return Json(new { success = true });
        }

        // Live log polling: returns real DB entries newer than the given UTC timestamp
        [HttpGet]
        public IActionResult GetNewLogs(string since)
        {
            if (CheckSessionInactivity()) return Json(new { success = false });
            if (!HasPermission("read:logs")) return Json(new { success = false });

            if (!DateTime.TryParse(since, null, System.Globalization.DateTimeStyles.RoundtripKind, out var sinceDate))
                sinceDate = DateTime.UtcNow.AddSeconds(-10);

            var logsQuery = _context.AuditLogs.Where(l => l.CreatedAt > sinceDate).OrderBy(l => l.CreatedAt).ToList();
            var userIds = logsQuery.Where(l => l.UserId.HasValue).Select(l => l.UserId!.Value).Distinct().ToList();
            var users = _context.Users.Where(u => userIds.Contains(u.UserId)).ToDictionary(u => u.UserId, u => string.IsNullOrEmpty(u.Email) ? u.FullName : u.Email);

            var logs = logsQuery
                .Select(l => new {
                    action   = l.Action,
                    details  = l.Details,
                    userId   = l.UserId != null && users.TryGetValue(l.UserId.Value, out var email) ? email : (l.UserId != null ? l.UserId.ToString() : "System"),
                    ip       = l.IpAddress ?? "",
                    time     = l.CreatedAt.AddHours(8).ToString("HH:mm:ss"),
                    isoTime  = l.CreatedAt.ToString("o")
                })
                .ToList();

            return Json(new { success = true, logs });
        }

        [HttpPost]
        public IActionResult ActionSuspendDevice(Guid deviceId)
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });
            if (!HasPermission("manage:devices")) return Json(new { success = false, message = "unauthorized" });

            var dev = _context.Devices.FirstOrDefault(d => d.DeviceId == deviceId);
            if (dev != null)
            {
                dev.Status = dev.Status == "Suspended" ? "Active" : "Suspended";
                _context.SaveChanges();
                return Json(new { success = true, status = dev.Status });
            }
            return Json(new { success = false });
        }

        [HttpPost]
        public IActionResult ActionApproveDevice(Guid deviceId)
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });
            if (!HasPermission("manage:devices")) return Json(new { success = false, message = "unauthorized" });

            var dev = _context.Devices.FirstOrDefault(d => d.DeviceId == deviceId);
            if (dev != null)
            {
                dev.Status = "Approved";
                _context.SaveChanges();
                return Json(new { success = true, status = dev.Status });
            }
            return Json(new { success = false });
        }

        [HttpPost]
        public IActionResult ActionRevokeDevice(Guid deviceId)
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });
            if (!HasPermission("manage:devices")) return Json(new { success = false, message = "unauthorized" });

            var dev = _context.Devices
                .FirstOrDefault(d => d.DeviceId == deviceId);
            if (dev != null)
            {
                // 1. Delete all FIDO2 credentials tied to this device
                var creds = _context.Credentials.Where(c => c.DeviceId == deviceId).ToList();
                _context.Credentials.RemoveRange(creds);

                // 2. Kill any active sessions from this device
                var sessions = _context.AuthSessions
                    .Where(s => s.DeviceId == deviceId && s.IsActive)
                    .ToList();
                foreach (var s in sessions)
                {
                    s.IsActive = false;
                    s.RevokedAt = DateTime.UtcNow;
                }

                // 3. Reset the device owner's status → PendingEnrollment if they have no other devices/passkeys left
                var owner = _context.Users.FirstOrDefault(u => u.UserId == dev.UserId);
                if (owner != null && owner.Email != "superadmin@university.edu")
                {
                    var remainingDevicesCount = _context.Devices.Count(d => d.UserId == dev.UserId && d.DeviceId != deviceId);
                    var remainingCredsCount = _context.Credentials.Count(c => c.UserId == dev.UserId && c.DeviceId != deviceId);

                    if (remainingDevicesCount == 0 && remainingCredsCount == 0)
                    {
                        owner.Status = "PendingEnrollment";
                    }
                }

                // 4. Remove the device itself
                _context.Devices.Remove(dev);

                _context.SaveChanges();

                return Json(new { success = true });
            }
            return Json(new { success = false });
        }

        [HttpPost]
        public IActionResult ActionRegisterDevice(string deviceName, string deviceType, string mac, string ownerName)
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });
            if (!HasPermission("manage:devices")) return Json(new { success = false, message = "unauthorized" });

            if (string.IsNullOrWhiteSpace(deviceName) || string.IsNullOrWhiteSpace(ownerName))
            {
                return Json(new { success = false, message = "Invalid parameters" });
            }

            var user = _context.Users.FirstOrDefault(u => u.FullName == ownerName);
            if (user == null)
            {
                return Json(new { success = false, message = "Owner not found" });
            }

            var device = new Device
            {
                DeviceId = Guid.NewGuid(),
                UserId = user.UserId,
                DeviceName = deviceName,
                DeviceType = deviceType ?? "Laptop",
                RegisteredAt = DateTime.UtcNow,
                Status = "Approved"
            };

            _context.Devices.Add(device);
            _context.SaveChanges();

            var log = new AuditLog
            {
                UserId = GetAuthenticatedUser()?.UserId,
                DeviceId = device.DeviceId.ToString(),
                Action = "Admin Device Registered",
                Details = $"Admin registered device '{deviceName}' for user '{ownerName}' (MAC: {mac}).",
                IpAddress = GetClientIp(),
                CreatedAt = DateTime.UtcNow
            };
            _context.AuditLogs.Add(log);
            _context.SaveChanges();

            return Json(new { success = true });
        }

        [HttpPost]
        public IActionResult ActionTerminateSession(Guid sessionId)
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });
            if (!HasPermission("manage:sessions")) return Json(new { success = false, message = "unauthorized" });

            var ses = _context.AuthSessions.FirstOrDefault(s => s.AuthSessionId == sessionId);
            if (ses != null)
            {
                ses.IsActive = false;
                ses.RevokedAt = DateTime.UtcNow;
                _context.SaveChanges();
                return Json(new { success = true });
            }
            return Json(new { success = false });
        }

        [HttpPost]
        public IActionResult ActionTerminateAllOther(string currentUserName)
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });
            if (!HasPermission("manage:sessions")) return Json(new { success = false, message = "unauthorized" });

            Request.Cookies.TryGetValue("portal_session_token", out string? currentSessionToken);

            // Fetch only non-expired other active sessions.
            // Fix: Filtering by s.ExpiresAt > DateTime.UtcNow matches the UI's table constraints,
            // preventing the mismatch where the admin is told 8 sessions were terminated when only 0 or 1 were visible.
            var sessionsToTerminate = _context.AuthSessions
                .Where(s => s.IsActive && s.ExpiresAt > DateTime.UtcNow && s.SessionToken != currentSessionToken)
                .ToList();

            foreach (var s in sessionsToTerminate)
            {
                s.IsActive = false;
                s.RevokedAt = DateTime.UtcNow;
            }
            _context.SaveChanges();
            return Json(new { success = true, count = sessionsToTerminate.Count });
        }

        [HttpPost]
        public IActionResult ActionCreateUser(string username, string email, string roleId, string verificationDoc, string detail)
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });

            if (!HasPermission("manage:users"))
            {
                return Json(new { success = false, message = "Only admins can create user accounts." });
            }

            if (string.IsNullOrWhiteSpace(username) ||
                string.IsNullOrWhiteSpace(email) ||
                string.IsNullOrWhiteSpace(roleId) ||
                string.IsNullOrWhiteSpace(verificationDoc))
            {
                return Json(new { success = false, message = "User identity, role, and verification record are required." });
            }

            var usernameTrimmed = username.Trim();
            var emailTrimmed = email.Trim();
            var verificationDocTrimmed = verificationDoc.Trim();

            if (usernameTrimmed.Length < 3)
            {
                return Json(new { success = false, message = "Full name must be at least 3 characters long." });
            }

            if (!System.Text.RegularExpressions.Regex.IsMatch(usernameTrimmed, @"^[a-zA-Z\s.-]+$"))
            {
                return Json(new { success = false, message = "Full name can only contain letters, spaces, dots, and hyphens." });
            }

            if (!System.Text.RegularExpressions.Regex.IsMatch(emailTrimmed, @"^[^\s@]+@[^\s@]+\.[^\s@]+$"))
            {
                return Json(new { success = false, message = "Please enter a valid email address format." });
            }

            if (verificationDocTrimmed.Length < 5)
            {
                return Json(new { success = false, message = "Verification document information must be at least 5 characters long." });
            }

            if (_context.Users.Any(u => u.Email == emailTrimmed))
            {
                return Json(new { success = false, message = "A user with this email already exists." });
            }

            var role = Roles.FirstOrDefault(r => r.RoleId == roleId);
            if (role == null)
            {
                return Json(new { success = false, message = "Invalid role selected." });
            }
            if (roleId == "admin")
            {
                return Json(new { success = false, message = "Admins cannot create other administrator accounts." });
            }

            var randId = (roleId == "student" ? "S" : roleId == "lecturer" ? "L" : "A") + Random.Shared.Next(100000, 999999).ToString() + "B";

            var user = new User
            {
                RoleId = roleId,
                FullName = usernameTrimmed,
                StudentStaffId = randId,
                Email = emailTrimmed,
                PhoneNo = "+6013-333-3333",
                Address = string.IsNullOrWhiteSpace(detail) ? "N/A" : detail.Trim(),
                Status = "PendingEnrollment"
            };
            _context.Users.Add(user);
            _context.SaveChanges();

            // Log account creation activity for security and traceability
            var log = new AuditLog
            {
                UserId = user.UserId,
                Action = "Account Provisioned",
                Details = $"Admin created account {user.FullName} ({role.RoleName}). Identity manually verified via {verificationDocTrimmed}. Status: PendingEnrollment until FIDO2 registration is completed.",
                IpAddress = GetClientIp(),
                CreatedAt = DateTime.UtcNow
            };
            _context.AuditLogs.Add(log);
            _context.SaveChanges();

            return Json(new { success = true, userId = user.UserId });
        }

        [HttpPost]
        public IActionResult ActionDeleteUser(string userId)
        {
            if (CheckSessionInactivity()) return Json(new { success = false, message = "session_expired" });
            if (!HasPermission("manage:users")) return Json(new { success = false, message = "unauthorized" });

            if (!Guid.TryParse(userId, out var userGuid)) 
                return Json(new { success = false, message = "Invalid User ID." });

            var user = _context.Users.FirstOrDefault(u => u.UserId == userGuid);
            if (user == null) 
                return Json(new { success = false, message = "User not found." });

            // Prevent deleting target if it's the current user
            var currentUser = GetAuthenticatedUser();
            if (currentUser != null && currentUser.UserId == userGuid)
            {
                return Json(new { success = false, message = "You cannot delete your own account." });
            }

            // Prevent deleting the primary superadmin seed account
            if (user.Email == "superadmin@university.edu")
            {
                return Json(new { success = false, message = "The system administrator account is protected and cannot be deleted." });
            }

            // Remove FIDO2 Credentials associated with the user
            var credentials = _context.Credentials.Where(c => c.UserId == userGuid).ToList();
            _context.Credentials.RemoveRange(credentials);

            // Terminate and remove all active sessions associated with the user
            var sessions = _context.AuthSessions.Where(s => s.UserId == userGuid).ToList();
            _context.AuthSessions.RemoveRange(sessions);

            // Remove all registered devices associated with the user
            var devices = _context.Devices.Where(d => d.UserId == userGuid).ToList();
            _context.Devices.RemoveRange(devices);

            // Dissociate user challenges
            var challenges = _context.AuthChallenges.Where(c => c.UserId == userGuid).ToList();
            foreach (var challenge in challenges)
            {
                challenge.UserId = null;
            }

            // Dissociate user audit logs to preserve logs history
            var logs = _context.AuditLogs.Where(l => l.UserId == userGuid).ToList();
            foreach (var l in logs)
            {
                l.UserId = null;
            }

            // Remove user from context
            _context.Users.Remove(user);
            
            // Log user deletion activity
            var deleteLog = new AuditLog
            {
                UserId = currentUser?.UserId,
                Action = "Account Deleted",
                Details = $"Admin deleted account: {user.FullName} ({user.Email}) with Staff/Student ID: {user.StudentStaffId}.",
                IpAddress = GetClientIp(),
                CreatedAt = DateTime.UtcNow
            };
            _context.AuditLogs.Add(deleteLog);

            _context.SaveChanges();

            return Json(new { success = true });
        }

        private void SetLayoutViewBag(string role)
        {
            Request.Cookies.TryGetValue("portal_name", out string? name);
            Request.Cookies.TryGetValue("portal_id", out string? id);
            Request.Cookies.TryGetValue("portal_email", out string? email);

            ViewBag.UserRole = Roles
                .Where(r => r.RoleId == role)
                .Select(r => r.RoleName)
                .FirstOrDefault() ?? "Student";
            ViewBag.UserName = name ?? "Alex Mercer";
            ViewBag.UserId = id ?? "S10248592";
            ViewBag.UserEmail = email ?? "student@portal.edu";
            ViewBag.RoleId = role;
            ViewBag.Role = role;

            // Find user in database to pull additional properties
            var user = _context.Users.FirstOrDefault(u => u.Email == email || u.FullName == name);
            ViewBag.FullName = user != null ? user.FullName : (name ?? "Alex Mercer");
            if (user != null)
            {
                ViewBag.UserPhone = user.PhoneNo;
                ViewBag.UserAddress = user.Address;
            }
            else
            {
                ViewBag.UserPhone = "+6012-345-6789";
                ViewBag.UserAddress = "742 Evergreen Terrace, Selangor, MY";
            }

            // Retrieve local network IP address dynamically
            var localIp = "127.0.0.1";
            try
            {
                using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
                {
                    socket.Connect("8.8.8.8", 65530);
                    var endPoint = socket.LocalEndPoint as IPEndPoint;
                    localIp = endPoint?.Address.ToString() ?? "127.0.0.1";
                }
            }
            catch
            {
                try
                {
                    var host = Dns.GetHostEntry(Dns.GetHostName());
                    foreach (var ip in host.AddressList)
                    {
                        if (ip.AddressFamily == AddressFamily.InterNetwork && !ip.ToString().StartsWith("127."))
                        {
                            localIp = ip.ToString();
                            break;
                        }
                    }
                }
                catch { }
            }
            ViewBag.LocalIP = localIp;
        }

    }
}
