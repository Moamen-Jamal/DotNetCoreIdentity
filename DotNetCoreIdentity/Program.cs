using DotNetCoreIdentity.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Identity.UI.Services;
using DotNetCoreIdentity.Services;
using DotNetCoreIdentity.Authorization;
using Microsoft.AspNetCore.Authorization;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services
    .AddIdentityCore<IdentityUser>(options =>
    {
        options.SignIn.RequireConfirmedAccount = true;
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

var jwtSection = builder.Configuration.GetSection("Jwt");
var jwtKey = jwtSection.GetValue<string>("Key") ?? throw new InvalidOperationException("JWT Key not configured");
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = jwtSection.GetValue<string>("Issuer"),
            ValidAudience = jwtSection.GetValue<string>("Audience"),
            IssuerSigningKey = signingKey,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });

builder.Services.AddControllersWithViews();

builder.Services.AddSingleton<IEmailSender, EmailSender>();
builder.Services.AddSingleton<JwtTokenService>();
builder.Services.AddScoped<IdentitySeeder>();
builder.Services.AddSingleton<IAuthorizationHandler, PermissionHandler>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CanManageUsers", policy =>
        policy.RequireAuthenticatedUser()
              .AddRequirements(new PermissionRequirement("manage_users")));
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<IdentitySeeder>();
    await seeder.SeedAsync();
}

app.Run();