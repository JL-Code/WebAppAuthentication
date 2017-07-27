using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using WebAppAuthentication.Entities;

namespace WebAppAuthentication
{
    /// <summary>
    /// 认证服务代理 继承OAuthAuthorizationServerProvider（包含4种认证授权方式）
    /// </summary>
    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {

            string clientId = string.Empty;
            string clientSecret = string.Empty;
            Client client = null;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            if (context.ClientId == null)
            {
                //Remove the comments from the below line context.SetError, and invalidate context 
                //if you want to force sending clientId/secrects once obtain access tokens. 
                context.Validated();
                //context.SetError("invalid_clientId", "ClientId should be sent.");
                return Task.FromResult<object>(null);
            }

            using (AuthRepository _repo = new AuthRepository())
            {
                client = _repo.FindClient(context.ClientId);
            }

            if (client == null)
            {
                context.SetError("invalid_clientId", string.Format("Client '{0}' is not registered in the system.", context.ClientId));
                return Task.FromResult<object>(null);
            }

            if (client.ApplicationType == ApplicationTypeEnum.NativeConfidential)
            {
                if (string.IsNullOrWhiteSpace(clientSecret))
                {
                    context.SetError("invalid_clientId", "Client secret should be sent.");
                    return Task.FromResult<object>(null);
                }
                else
                {
                    if (client.Secret != Helper.GetHash(clientSecret))
                    {
                        context.SetError("invalid_clientId", "Client secret is invalid.");
                        return Task.FromResult<object>(null);
                    }
                }
            }

            if (!client.Active)
            {
                context.SetError("invalid_clientId", "Client is inactive.");
                return Task.FromResult<object>(null);
            }
            //在Owin上下文中存储客户端允许的起始和刷新令牌生命周期值，以便在生成刷新令牌并设置其到期时间后可用。
            context.OwinContext.Set("as:clientAllowedOrigin", client.AllowedOrigin);
            context.OwinContext.Set("as:clientRefreshTokenLifeTime", client.RefreshTokenLifeTime.ToString());

            context.Validated();
            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// “GrantResourceOwnerCredentials”负责验证发送到授权服务器的令牌端点的用户名和密码，因此我们将使用我们之前创建的“AuthRepository”类，并调用方法“FindUser”来检查用户名和密码是否为有效。
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        //public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        //{
        //    //为了允许在标记中间件提供程序上使用CORS，我们需要将标题“Access-Control-Allow-Origin”添加到Owin上下文中，如果您忘记了这一点，则当您尝试从浏览器调用它时，生成令牌将失败。不是这样，允许CORS用于令牌中间件提供程序不适用于下一步将添加的ASP.NET Web API。
        //    context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

        //    using (AuthRepository _repo = new AuthRepository())
        //    {
        //        IdentityUser user = await _repo.FindUser(context.UserName, context.Password);
        //        if (user == null)
        //        {
        //            context.SetError("invalid_grant", "The user name or password is incorrect.");
        //            return;
        //        }
        //    }

        //    var identity = new ClaimsIdentity(context.Options.AuthenticationType);
        //    identity.AddClaim(new Claim("sub", context.UserName));
        //    identity.AddClaim(new Claim("role", "user"));

        //    context.Validated(identity);

        //}
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            //从Owin上下文读取该客户端的允许原始值，然后使用此值将头“Access-Control-Allow-Origin”添加到Owin上下文响应中，通过执行此操作以及我们将阻止使用的任何JavaScript应用程序相同的客户端ID来构建另一个域上托管的JavaScript应用程序; 因为来自此应用程序的所有请求的来源将来自不同的域，后端API将返回405状态。
            var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");

            if (allowedOrigin == null) allowedOrigin = "*";

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });
            //如果是这样，我们将检查资源所有者的用户名/密码，如果是这种情况，我们将为此用户生成一组声明以及包含客户端id和userName的身份验证属性，这些属性需要接下来的步骤。
            using (AuthRepository _repo = new AuthRepository())
            {
                IdentityUser user = await _repo.FindUser(context.UserName, context.Password);

                if (user == null)
                {
                    context.SetError("invalid_grant", "The user name or password is incorrect.");
                    return;
                }
            }

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);

            //为此用户生成一组声明以及包含客户端id和userName的身份验证属性，这些属性需要接下来的步骤。
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            identity.AddClaim(new Claim("sub", context.UserName));
            identity.AddClaim(new Claim("role", "user"));

            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    {
                        "as:client_id", context.ClientId ??string.Empty
                    },
                    {
                        "userName", context.UserName
                    }
                });

            var ticket = new AuthenticationTicket(identity, props);
            //现在当我们称之为“context.Validated（ticket）”时，会在幕后生成访问令牌
            context.Validated(ticket);

        }

        /// <summary>
        /// 授予刷新令牌
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["as:client_id"];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
                return Task.FromResult<object>(null);
            }

            // Change auth ticket for refresh token requests 改变授权票刷新令牌的请求
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);
            newIdentity.AddClaim(new Claim("新的声明", "新的值"));

            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            context.Validated(newTicket);

            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }
    }
}