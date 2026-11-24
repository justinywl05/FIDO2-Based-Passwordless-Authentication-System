using Fido2NetLib;
using NexusUniversityWebPortal.AuthBackend.Data;
using NexusUniversityWebPortal.AuthBackend.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

// Configure Forwarded Headers to trust ngrok's proxy settings
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddOpenApi();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddFido2(options =>
{
    options.ServerDomain = builder.Configuration["fido2:ServerDomain"]!;
    options.ServerName = builder.Configuration["fido2:ServerName"]!;
    options.Origins = builder.Configuration
        .GetSection("fido2:Origins")
        .Get<HashSet<string>>() ?? new HashSet<string>();
});

builder.Services.AddScoped<Fido2Service>();
builder.Services.AddScoped<AuditLogService>();

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(builder.Environment.ContentRootPath, ".aspnet-keys")));

var app = builder.Build();

// 1. Read ngrok proxy headers immediately
app.UseForwardedHeaders();

// 2. STRICT SECURITY MIDDLEWARE: Drops HTTP requests completely with a 403 Forbidden error
app.Use(async (context, next) =>
{
    if (!string.Equals(context.Request.Scheme, "https", StringComparison.OrdinalIgnoreCase))
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        await context.Response.WriteAsync("Security Violation: Secure Connection (HTTPS) is Required.");
        return; // Stops execution dead in its tracks
    }
    await next();
});

// 3. Environment routing rules
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}
else
{
    app.MapOpenApi();
}

// 4. Force browser-level strict transport security
app.UseHsts();

app.UseRouting();
app.UseAuthorization();

app.MapStaticAssets();
app.MapControllers();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Portal}/{action=Login}/{id?}")
    .WithStaticAssets();

app.Run();