using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace DotNetCoreIdentity.Controllers
{
    [Authorize(Policy = "CanManageUsers")]
    public class AdminController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AdminController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        [HttpPost]
        public async Task<IActionResult> AddRole(string userEmail, string role)
        {
            var user = await _userManager.FindByEmailAsync(userEmail);
            if (user == null) return NotFound();
            if (!await _roleManager.RoleExistsAsync(role)) await _roleManager.CreateAsync(new IdentityRole(role));
            await _userManager.AddToRoleAsync(user, role);
            return Ok();
        }

        [HttpPost]
        public async Task<IActionResult> AddClaim(string userEmail, string type, string value)
        {
            var user = await _userManager.FindByEmailAsync(userEmail);
            if (user == null) return NotFound();
            await _userManager.AddClaimAsync(user, new Claim(type, value));
            return Ok();
        }
    }
}


