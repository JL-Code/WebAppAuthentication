using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using System.Web.Http;

[assembly: OwinStartup(typeof(JwtCustomAuth.Startup))]

namespace JwtCustomAuth
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {

            var config = new HttpConfiguration();
            WebApiConfig.Register(config);

        }
    }
}
