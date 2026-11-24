using System;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Objects;
using NexusUniversityWebPortal.AuthBackend.Data;
using NexusUniversityWebPortal.AuthBackend.Models;
using Microsoft.EntityFrameworkCore;

namespace NexusUniversityWebPortal.AuthBackend.Services
{
    /// <summary>
    /// Service to handle FIDO2 credential generation and verification.
    /// </summary>
    public class Fido2Service
    {
        private readonly IFido2 _fido2;
        private readonly ApplicationDbContext _context;

        public Fido2Service(IFido2 fido2, ApplicationDbContext context)
        {
            _fido2 = fido2;
            _context = context;
        }

        /// <summary>
        /// Generates the credential create options for a user and saves the FIDO2 challenge.
        /// </summary>
        /// <param name="user">The user for whom to generate options.</param>
        /// <param name="purpose">
        /// The purpose to stamp on the AuthChallenge record.
        /// Use "Register" for Phase 2 (user-controlled) and "InitialRegistration-FIDO2" for Phase 1 (admin-initiated).
        /// </param>
        public async Task<CredentialCreateOptions> GenerateRegisterOptionsAsync(User user, string purpose = "Register")
        {
            // Get existing keys to prevent the same authenticator from being registered twice
            var existingCredentials = await _context.Credentials
                .Where(c => c.UserId == user.UserId)
                .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
                .ToListAsync();

            var fido2User = new Fido2User
            {
                DisplayName = string.IsNullOrWhiteSpace(user.FullName) ? user.Email : user.FullName,
                Name = user.Email,
                Id = user.UserId.ToByteArray()
            };

            // Prefer platform authenticators (built-in biometrics) and require user verification.
            var authenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = ResidentKeyRequirement.Discouraged,
                UserVerification = UserVerificationRequirement.Preferred
            };

            var options = _fido2.RequestNewCredential(new RequestNewCredentialParams
            {
                User = fido2User,
                ExcludeCredentials = existingCredentials,
                AuthenticatorSelection = authenticatorSelection,
                AttestationPreference = AttestationConveyancePreference.None
            });

            // Persist the entire options JSON so we can reconstruct it during the verify step
            var challengeRecord = new AuthChallenge
            {
                UserId = user.UserId,
                Challenge = options.ToJson(),
                Purpose = purpose,
                ExpiresAt = DateTime.UtcNow.AddMinutes(5),
                IsUsed = false
            };

            _context.AuthChallenges.Add(challengeRecord);
            await _context.SaveChangesAsync();

            return options;
        }

        public async Task<RegisteredPublicKeyCredential> VerifyRegisterResponseAsync(AuthenticatorAttestationRawResponse attestationResponse, AuthChallenge challengeRecord)
        {
            var options = CredentialCreateOptions.FromJson(challengeRecord.Challenge);

            // Callback to verify uniqueness of credential ID
            IsCredentialIdUniqueToUserAsyncDelegate callback = async (IsCredentialIdUniqueToUserParams args, CancellationToken cancellationToken) =>
            {
                var existing = await _context.Credentials.FirstOrDefaultAsync(c => c.CredentialId == args.CredentialId, cancellationToken);
                return existing == null;
            };

            var result = await _fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = attestationResponse,
                OriginalOptions = options,
                IsCredentialIdUniqueToUserCallback = callback
            });

            return result;
        }

        public async Task<AssertionOptions> GenerateLoginOptionsForCdaAsync(User user, System.Collections.Generic.List<PublicKeyCredentialDescriptor> allowedCredentials)
        {
            // Tag every descriptor with the "hybrid" transport so the browser shows the QR/Bluetooth cross-device picker
            var hybridCredentials = allowedCredentials
                .Select(c => new PublicKeyCredentialDescriptor(c.Type, c.Id, new[] { AuthenticatorTransport.Hybrid }))
                .ToList();

            var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams
            {
                AllowedCredentials = hybridCredentials,
                UserVerification = UserVerificationRequirement.Required   // biometric mandatory for CDA
            });

            var challengeRecord = new AuthChallenge
            {
                UserId = user.UserId,
                Challenge = options.ToJson(),
                Purpose = "Login",
                ExpiresAt = DateTime.UtcNow.AddMinutes(5),
                IsUsed = false
            };

            _context.AuthChallenges.Add(challengeRecord);
            await _context.SaveChangesAsync();

            return options;
        }

        public async Task<AssertionOptions> GenerateLoginOptionsAsync(User user, System.Collections.Generic.List<PublicKeyCredentialDescriptor> allowedCredentials)
        {
            var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams
            {
                AllowedCredentials = allowedCredentials,
                UserVerification = UserVerificationRequirement.Preferred
            });

            var challengeRecord = new AuthChallenge
            {
                UserId = user.UserId,
                Challenge = options.ToJson(),
                Purpose = "Login",
                ExpiresAt = DateTime.UtcNow.AddMinutes(5),
                IsUsed = false
            };

            _context.AuthChallenges.Add(challengeRecord);
            await _context.SaveChangesAsync();

            return options;
        }

        public async Task<VerifyAssertionResult> VerifyLoginResponseAsync(AuthenticatorAssertionRawResponse assertionResponse, AuthChallenge challengeRecord, byte[] publicKey, uint storedSignCount)
        {
            var options = AssertionOptions.FromJson(challengeRecord.Challenge);

            // Callback to verify the signCount is greater than the stored one
            IsUserHandleOwnerOfCredentialIdAsync callback = async (IsUserHandleOwnerOfCredentialIdParams args, CancellationToken cancellationToken) =>
            {
                var existing = await _context.Credentials.FirstOrDefaultAsync(c => c.CredentialId == args.CredentialId, cancellationToken);
                return existing != null && existing.UserId == challengeRecord.UserId;
            };

            var result = await _fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = assertionResponse,
                OriginalOptions = options,
                StoredPublicKey = publicKey,
                StoredSignatureCounter = storedSignCount,
                IsUserHandleOwnerOfCredentialIdCallback = callback
            });

            return result;
        }
    }
}
