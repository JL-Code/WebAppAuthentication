using System;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.Security.Jwt;
using System.Web.Http;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Security;
//设置启动类
[assembly: OwinStartup(typeof(JWTWebAuthentication.Startup))]

namespace JWTWebAuthentication
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {

            //配置OAuth授权认证
            ConfigureOAuth(app);

            var config = new HttpConfiguration();

            WebApiConfig.Register(config);

            //运行跨域
            app.UseCors(CorsOptions.AllowAll);

            app.UseWebApi(config);

        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            var authServerOptions = new OAuthAuthorizationServerOptions()
            {
                //请求路径，客户端应用程序将通过该路径重定向用户代理以获取用户对颁发令牌的同意。
                TokenEndpointPath = new PathString("/token"),
                //令牌过期时间 30分钟过期
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(30),
                //AccessTokenFormat = new JwtFormat(new TokenValidationParameters()),
                //处理授权服务
                Provider = new MyOAuthAuthorizationServerProvider(),
                //生成Jwt令牌
                AccessTokenFormat = new MyJwtTokenFormat(),
#if DEBUG
                AllowInsecureHttp = true
#endif
            };
            
            var jwtOptions = new JwtBearerAuthenticationOptions()
            {
                AuthenticationMode = AuthenticationMode.Active,
                AllowedAudiences = new[] { "ng" },
                IssuerSecurityTokenProviders = new IIssuerSecurityTokenProvider[]
                {
                  new 
                }
            };
            //注册Owin中间件发布令牌
            app.UseOAuthAuthorizationServer(authServerOptions);
            //Authentication 中间件 在请求中验证Token并设置用户的身份
            app.UseJwtBearerAuthentication(jwtOptions);
        }
    }
}
