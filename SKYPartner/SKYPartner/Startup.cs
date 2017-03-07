using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(SKYPartner.Startup))]
namespace SKYPartner
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
