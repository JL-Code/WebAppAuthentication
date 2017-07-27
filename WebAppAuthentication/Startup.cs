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
            //我们已经将令牌的到期时间设定为24小时，所以如果用户在发布时间24小时后尝试使用相同的令牌进行身份验证，那么他的请求将被拒绝，并返回HTTP状态代码401。
            //我们已经指定了如何验证用户要求在名为“SimpleAuthorizationServerProvider”的自定义类中的令牌的凭据的实现。
            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"),
                //设置令牌过期时间
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(30),
                //令牌认证服务
                Provider = new SimpleAuthorizationServerProvider(),
                //刷新令牌代理
                RefreshTokenProvider = new SimpleRefreshTokenProvider()
            };
            // 将OAuthServerOptions传递给扩展方法“UseOAuthAuthorizationServer”，所以我们将把认证中间件添加到管道中
            // Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
        }
    }
}
