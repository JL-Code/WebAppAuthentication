using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using OAuth.Pack;
using System;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JWTWebAuthentication
{
    /// <summary>
    /// 此类的目的是将有关已验证用户的信息编码并签署到字符串中
    /// </summary>
    public class MyJwtTokenFormat : ISecureDataFormat<AuthenticationTicket>
    {
        /// <summary>
        /// 生成Jwt令牌信息
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public string Protect(AuthenticationTicket data)
        {
            if (data == null)
                throw new AggregateException(nameof(data));
            //生成jwt的id jti
            //从配置文件中读取 jwt的issuer 发行者 audience 受众  expires 过期时间  key 加密证书
            var expires = data.Properties.ExpiresUtc.GetValueOrDefault().DateTime;
            var jwt = TokenManager.CreateJwtToken(expires, data.Identity.Claims);
            return jwt;
        }

        public AuthenticationTicket Unprotect(string protectedText)
        {
            throw new NotImplementedException();
        }
    }
}