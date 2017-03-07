using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(PartnerSKY.Startup))]
namespace PartnerSKY
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
