using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Mvc;
using System.Collections.Generic;
using System.Security.Claims;

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
        public IActionResult Login(string userName, string password, string returnUrl = null)
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
                Context.Authentication.SignIn("Cookies", new ClaimsPrincipal(id));

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

        public IActionResult ExternalCallback()
        {
            var externalId = Context.Authentication.Authenticate("Temp");

            // check external identity - e.g. to see if registration is required
            // or to associate account with current login etc
            // name identifier is the unique id of the user in the context of the external provider
            var userId = externalId.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;

            var name = externalId.Principal.FindFirst(ClaimTypes.Name).Value;
            var email = externalId.Principal.FindFirst(ClaimTypes.Email).Value;

            // add some application claims from profile database
            var role = new Claim("role", "PremiumUser");

            var newId = new ClaimsIdentity("application", "name", "role");
            newId.AddClaim(new Claim("name", name));
            newId.AddClaim(new Claim("email", email));
            newId.AddClaim(role);

            // sign in user with main cookie
            Context.Authentication.SignIn("Cookies", new ClaimsPrincipal(newId));

            // delete temp cookie
            Context.Authentication.SignOut("Temp");

            return Redirect("/home/secure");
        }

        public IActionResult Logoff()
        {
            Context.Authentication.SignOut();
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