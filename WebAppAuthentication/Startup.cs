using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using System.Web.Http;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.Cors;

[assembly: OwinStartup(typeof(WebAppAuthentication.Startup))]

namespace WebAppAuthentication
{
    /// <summary>
    /// 我们上面实现的很简单，一旦我们的服务器启动，这个类将被触发，注意“assembly”属性，它指出启动时要启动哪个类。“配置”方法接受“IAppBuilder”类型的参数，该参数将由主机在运行时提供。这个“app”参数是一个接口，用于为我们的Owin服务器编写应用程序。“HttpConfiguration”对象用于配置API路由，所以我们将这个对象传递给“WebApiConfig”类中的方法“Register”。
    /// 最后，我们将把“config”对象传递给扩展方法“UseWebApi”，它将负责将ASP.NET Web API连接到我们的Owin服务器管道。
    /// </summary>
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureOAuth(app);

            var config = new HttpConfiguration();
            WebApiConfig.Register(config);
            //运行asp.net webapi 跨域
            app.UseCors(CorsOptions.AllowAll);
            app.UseWebApi(config);
        }

        /// <summary>
        /// 配置OAuth认证授权相关
        /// </summary>
        /// <param name="app"></param>
        public void ConfigureOAuth(IAppBuilder app)
        {
            //生成令牌的路径将是：“http：// localhost：port / token”。我们将看到我们将如何在后续步骤中发出HTTP POST请求以生成令牌。
            //我们已经指定了如何验证用户要求在名为“SimpleAuthorizationServerProvider”的自定义类中的令牌的凭据的实现。
            //选项类提供控制授权服务器中间件行为所需的信息
            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                //客户端应用程序直接通过 OAuth 协议与之通信的请求路径。 必须以前导斜杠开头，如“/Token”。
                //如果为客户端颁发了 client_secret，则必须将其提供给此终结点。
                TokenEndpointPath = new PathString("/api/oauth2/token"),
                //设置令牌过期时间
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(2),
                //令牌认证服务 用于处理授权服务器中间件引发的事件
                Provider = new SimpleAuthorizationServerProvider(),
                //用于生成访问令牌的代理
                //AccessTokenProvider = new SimpleAccessTokenProvider(),
                //用于生成刷新令牌的代理
                RefreshTokenProvider = new SimpleRefreshTokenProvider()
            };
            //向 OWIN Ｗeb 应用程序添加 OAuth2 授权服务器功能。 此中间件执行由 OAuth2 规范定义的授权和令牌终结点请求处理
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            //生成 OWIN 应用程序的 OAuth 持有者身份验证。
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
        }
    }
}
