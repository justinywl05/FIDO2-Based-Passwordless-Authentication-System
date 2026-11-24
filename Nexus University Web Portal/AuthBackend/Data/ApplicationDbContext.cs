using Microsoft.EntityFrameworkCore;
using NexusUniversityWebPortal.AuthBackend.Models;

namespace NexusUniversityWebPortal.AuthBackend.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Device> Devices { get; set; }
        public DbSet<Credential> Credentials { get; set; }
        public DbSet<AuthChallenge> AuthChallenges { get; set; }
        public DbSet<AuthSession> AuthSessions { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }


        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Force EF Core to create a Unique Index on the Email column
            modelBuilder.Entity<User>()
                .Property(u => u.Email)
                .HasMaxLength(256)
                .IsRequired();

            modelBuilder.Entity<User>()
                .HasIndex(u => u.Email)
                .IsUnique();

            // FIDO2 Credential DescriptorId works as a primary key
            modelBuilder.Entity<Credential>()
                .HasKey(c => c.CredentialId);

            // Establish 1-to-many relationship from User -> Devices
            modelBuilder.Entity<User>()
                .HasMany(u => u.Devices)
                .WithOne(d => d.User)
                .HasForeignKey(d => d.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // Establish 1-to-many relationship from Device -> Credentials
            modelBuilder.Entity<Device>()
                .HasMany(d => d.Credentials)
                .WithOne(c => c.Device)
                .HasForeignKey(c => c.DeviceId)
                .OnDelete(DeleteBehavior.Cascade);

            // Setup User -> Credentials
            modelBuilder.Entity<Credential>()
                .HasOne(c => c.User)
                .WithMany()
                .HasForeignKey(c => c.UserId)
                .OnDelete(DeleteBehavior.Restrict);

            // Setup User -> AuthSessions
            modelBuilder.Entity<User>()
                .HasMany(u => u.AuthSessions)
                .WithOne(s => s.User)
                .HasForeignKey(s => s.UserId)
                .OnDelete(DeleteBehavior.Restrict);

            // Setup Device -> AuthSessions
            modelBuilder.Entity<AuthSession>()
                .HasOne(s => s.Device)
                .WithMany()
                .HasForeignKey(s => s.DeviceId)
                .OnDelete(DeleteBehavior.SetNull);

            // Seed the Roaming Admin Account
            modelBuilder.Entity<User>().HasData(
                new User 
                { 
                    UserId = Guid.Parse("00000000-0000-0000-0000-000000000001"),
                    Email = "superadmin@university.edu",
                    FullName = "System Administrator",
                    StudentStaffId = "ADMIN-01",
                    RoleId = "admin",
                    Status = "Active",
                    CreatedAt = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                }
            );
        }
    }
}
