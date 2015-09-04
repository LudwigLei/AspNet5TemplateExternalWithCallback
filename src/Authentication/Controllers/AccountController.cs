using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Mvc;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authentication.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string userName, string password, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (!string.IsNullOrWhiteSpace(userName) && 
                userName == password)
            {
                var claims = new List<Claim>
                    {
                        new Claim("sub", userName),
                        new Claim("name", "Bob"),
                        new Claim("email", "bob@smith.com")
                    };

                var id = new ClaimsIdentity(claims, "local", "name", "role");
                await Context.Authentication.SignInAsync("Cookies", new ClaimsPrincipal(id));

                return RedirectToLocal(returnUrl);
            }

            return View();
        }

        public IActionResult External(string provider)
        {
            var props = new AuthenticationProperties
            {
                RedirectUri = "/account/externalCallback"
            };

            return new ChallengeResult(provider, props);
        }

        public async Task<IActionResult> ExternalCallback()
        {
            var externalId = await Context.Authentication.AuthenticateAsync("Temp");

            // check external identity - e.g. to see if registration is required
            // or to associate account with current login etc
            // name identifier is the unique id of the user in the context of the external provider
            var userId = externalId.FindFirst(ClaimTypes.NameIdentifier).Value;

            var name = externalId.FindFirst(ClaimTypes.Name).Value;
            var email = externalId.FindFirst(ClaimTypes.Email).Value;

            // add some application claims from profile database
            var role = new Claim("role", "PremiumUser");

            var newId = new ClaimsIdentity("application", "name", "role");
            newId.AddClaim(new Claim("name", name));
            newId.AddClaim(new Claim("email", email));
            newId.AddClaim(role);

            // sign in user with main cookie
            await Context.Authentication.SignInAsync("Cookies", new ClaimsPrincipal(newId));

            // delete temp cookie
            await Context.Authentication.SignOutAsync("Temp");

            return Redirect("/home/secure");
        }

        public async Task<IActionResult> Logoff()
        {
            await Context.Authentication.SignOutAsync("Cookies");
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }
    }
}