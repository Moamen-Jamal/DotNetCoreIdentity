using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace DotNetCoreIdentity.Data
{
    public class IdentitySeeder
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<IdentityUser> _userManager;

        public IdentitySeeder(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }

        public async Task SeedAsync()
        {
            // Seed roles
            var roles = new[] { "Admin", "User" };
            foreach (var role in roles)
            {
                if (!await _roleManager.RoleExistsAsync(role))
                {
                    await _roleManager.CreateAsync(new IdentityRole(role));
                }
            }

            // Optionally seed an admin user (demo)
            var adminEmail = "admin@demo.local";
            var adminUser = await _userManager.FindByEmailAsync(adminEmail);
            if (adminUser == null)
            {
                adminUser = new IdentityUser { UserName = adminEmail, Email = adminEmail, EmailConfirmed = true };
                var create = await _userManager.CreateAsync(adminUser, "Admin#12345");
                if (create.Succeeded)
                {
                    await _userManager.AddToRoleAsync(adminUser, "Admin");
                    await _userManager.AddClaimAsync(adminUser, new Claim("permission", "manage_users"));
                }
            }
            else
            {
                // ensure claim exists
                await _userManager.AddClaimAsync(adminUser, new Claim("permission", "manage_users"));
            }
        }
    }
}


