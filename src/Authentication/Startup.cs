using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Logging;

namespace Authentication
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.MinimumLevel = LogLevel.Information;
            loggerFactory.AddConsole();

            app.UseCookieAuthentication(options =>
            {
                options.LoginPath = "/account/login";

                options.AuthenticationScheme = "Cookies";
                options.AutomaticAuthentication = true;
            }, "main");

            app.UseCookieAuthentication(options =>
            {
                options.AuthenticationScheme = "Temp";
                options.AutomaticAuthentication = false;
            }, "external");

            app.UseGoogleAuthentication(options =>
            {
                options.ClientId = "434483408261-55tc8n0cs4ff1fe21ea8df2o443v2iuc.apps.googleusercontent.com";
                options.ClientSecret = "3gcoTrEDPPJ0ukn_aYYT6PWo";

                options.AuthenticationScheme = "Google";
                options.SignInScheme = "Temp";
            });

            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();
        }
    }
}
