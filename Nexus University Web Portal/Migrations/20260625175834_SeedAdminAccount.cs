using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace NexusUniversityWebPortal._COMBINED.Migrations
{
    /// <inheritdoc />
    public partial class SeedAdminAccount : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "Users",
                columns: new[] { "UserId", "Address", "CreatedAt", "Email", "FullName", "PhoneNo", "RoleId", "Status", "StudentStaffId" },
                values: new object[] { new Guid("11111111-1111-1111-1111-111111111111"), "", new DateTime(2026, 6, 25, 17, 58, 33, 746, DateTimeKind.Utc).AddTicks(9131), "superadmin@university.edu", "System Administrator", "", "admin", "Active", "ADMIN-01" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Users",
                keyColumn: "UserId",
                keyValue: new Guid("11111111-1111-1111-1111-111111111111"));
        }
    }
}
