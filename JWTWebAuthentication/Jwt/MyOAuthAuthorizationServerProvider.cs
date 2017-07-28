using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.Owin.Security;

namespace JWTWebAuthentication
{
    public class MyOAuthAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        /// <summary>
        /// 客户端身份验证
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId = string.Empty;
            string clientSecret = string.Empty;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }
            if (context.ClientId == null)
            {
                context.SetError("invalid_clientId", "client_Id is not set");
                return Task.FromResult<object>(null);
            }
            //在Owin上下文中存储客户端允许的起始和刷新令牌生命周期值，以便在生成刷新令牌并设置其到期时间后可用。
            //context.OwinContext.Set("as:clientAllowedOrigin", "*");
            context.Validated();
            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// 授予资源所有者证书
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            //从Owin上下文读取该客户端的允许原始值，然后使用此值将头“Access-Control-Allow-Origin”添加到Owin上下文响应中，通过执行此操作以及我们将阻止使用的任何JavaScript应用程序相同的客户端ID来构建另一个域上托管的JavaScript应用程序; 因为来自此应用程序的所有请求的来源将来自不同的域，后端API将返回405状态。
            var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");
            if (allowedOrigin == null) allowedOrigin = "*";
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });
            //检查资源所有者的用户名/密码，验证成功后为此用户生成一组声明以及包含客户端id和userName的身份验证属性。
            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                        //为此用户生成一组声明以及包含客户端id和userName的身份验证属性，这些属性需要接下来的步骤。
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            identity.AddClaim(new Claim("sub", context.UserName));
            identity.AddClaim(new Claim("isadmin", "True"));
            identity.AddClaim(new Claim("name", "mecode"));
            identity.AddClaim(new Claim("company", "衡泽科技"));

            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    {"as:client_id", context.ClientId ??string.Empty},
                    {"userName", context.UserName}
                });
            var ticket = new AuthenticationTicket(identity, props);
            //现在当我们称之为“context.Validated（ticket）”时，会在幕后生成访问令牌 调用 MyJwtTokenFormat的Protect方法
            context.Validated(ticket);
            return Task.FromResult<object>(null);
        }
    }
}