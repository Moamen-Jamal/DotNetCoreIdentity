using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace DotNetCoreIdentity.Controllers
{
    [Authorize]
    public class ProfileController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;

        public ProfileController(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToAction("Login", "Account");
            ViewBag.Email = user.Email;
            ViewBag.Roles = await _userManager.GetRolesAsync(user);
            ViewBag.Claims = (await _userManager.GetClaimsAsync(user)).Select(c => $"{c.Type}={c.Value}").ToList();
            ViewBag.TwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Enable2FA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToAction("Login", "Account");
            await _userManager.SetTwoFactorEnabledAsync(user, true);
            return RedirectToAction("Index");
        }

        [HttpPost]
        public async Task<IActionResult> Disable2FA()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToAction("Login", "Account");
            await _userManager.SetTwoFactorEnabledAsync(user, false);
            return RedirectToAction("Index");
        }
    }
}


