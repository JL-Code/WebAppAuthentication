using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Threading.Tasks;

namespace WebAppAuthentication
{
    /// <summary>
    /// 访问令牌代理 用于生成访问令牌
    /// </summary>
    public class SimpleAccessTokenProvider : AuthenticationTokenProvider
    {
        public override Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            return base.CreateAsync(context);
        }

        public override Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            return base.ReceiveAsync(context);
        }
    }
}