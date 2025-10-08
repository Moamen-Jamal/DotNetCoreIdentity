using System.Threading.Tasks;
using DotNetCoreIdentity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using DotNetCoreIdentity.Services;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace DotNetCoreIdentity.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly JwtTokenService _jwtTokenService;
        private readonly IEmailSender _emailSender;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, JwtTokenService jwtTokenService, IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtTokenService = jwtTokenService;
            _emailSender = emailSender;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (!ModelState.IsValid) return View(model);

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null || !await _userManager.IsEmailConfirmedAsync(user))
                {
                    ModelState.AddModelError(string.Empty, "Email not confirmed.");
                    return View(model);
                }
                var roles = await _userManager.GetRolesAsync(user);
                var userClaims = await _userManager.GetClaimsAsync(user);
                var (token, expires) = _jwtTokenService.GenerateToken(user!.Id, user.Email!, roles, userClaims);
                return View("Token", new TokenViewModel { Token = token, ExpiresUtc = expires });
            }
            if (result.RequiresTwoFactor)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null) { ModelState.AddModelError(string.Empty, "Invalid login attempt."); return View(model); }
                var code = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
                await _emailSender.SendEmailAsync(user.Email!, "Your verification code", $"Your verification code is: <strong>{code}</strong>");
                TempData["2fa_user"] = user.Id;
                TempData["remember_me"] = model.RememberMe;
                return RedirectToAction("Verify2FA");
            }
            if (result.IsLockedOut) { ModelState.AddModelError(string.Empty, "User account locked out."); return View(model); }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Verify2FA() => View(new TwoFactorViewModel());

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Verify2FA(TwoFactorViewModel model)
        {
            if (!ModelState.IsValid) return View(model);
            var userId = TempData["2fa_user"] as string;
            var rememberMe = TempData["remember_me"] as bool? ?? false;
            if (string.IsNullOrEmpty(userId))
            {
                ModelState.AddModelError(string.Empty, "Session expired. Please login again.");
                return View(model);
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) { ModelState.AddModelError(string.Empty, "Invalid verification attempt."); return View(model); }
            var result = await _signInManager.TwoFactorSignInAsync(TokenOptions.DefaultEmailProvider, model.Code, rememberMe, rememberClient: false);
            if (result.Succeeded)
            {
                var roles = await _userManager.GetRolesAsync(user);
                var userClaims = await _userManager.GetClaimsAsync(user);
                var (token, expires) = _jwtTokenService.GenerateToken(user!.Id, user.Email!, roles, userClaims);
                return View("Token", new TokenViewModel { Token = token, ExpiresUtc = expires });
            }
            if (result.IsLockedOut) { ModelState.AddModelError(string.Empty, "User account locked out."); return View(model); }
            ModelState.AddModelError(string.Empty, "Invalid code.");
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register(string? returnUrl = null) { ViewData["ReturnUrl"] = returnUrl; return View(); }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (!ModelState.IsValid) return View(model);

            var user = new IdentityUser { UserName = model.Email, Email = model.Email, EmailConfirmed = true };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code }, Request.Scheme);
                await _emailSender.SendEmailAsync(user.Email!, "Confirm your email", $"Please confirm your account by <a href='{callbackUrl}'>clicking here</a>.");
                return View("ConfirmEmailSent");
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View(model);
        }

        // With JWT there is no server-side logout. Clients should discard the token.

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return RedirectToAction("Index", "Home");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound("User not found");
            var result = await _userManager.ConfirmEmailAsync(user, code);
            if (result.Succeeded)
            {
                return View("EmailConfirmed");
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View("EmailConfirmed");
        }
    }
}


