using Microsoft.Owin.Security;
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
            //从配置文件中读取 jwt的issuer 发行者 audience 受众  expires 过期时间  key 加密证书
            var issuer = "mecode";
            var audience = "mywebapp";
            var jti = audience + expires.Millisecond + "postman_code";
            jti = MD5Util.GetMD5(jti);
            JwtSecurityToken token;
            string jwt;
            //获取签名证书
            //包含用于生成数字签名的加密密钥
            var handler = new JwtSecurityTokenHandler();
            var rsaparmeters = RSAUtil.GenerateAndSaveKey("E:\\");
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.ImportParameters(rsaparmeters);
                var singingKey = new RsaSecurityKey(rsa);
                var signingCredentials = new SigningCredentials(singingKey, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.RsaSha256Signature);
                var claimsIdentity = new ClaimsIdentity(data.Identity.Claims, "JWTTest");

                claimsIdentity.AddClaim(new Claim("jti", jti));
                claimsIdentity.AddClaim(new Claim("now", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")));
                var asymmetric = new AsymmetricSignatureProvider(singingKey, SecurityAlgorithms.RsaSha256Signature, true);
                token = handler.CreateToken(issuer, audience, claimsIdentity, null, expires, signingCredentials, asymmetric);
                jwt = handler.WriteToken(token);
            }
            return jwt;
        }

        public AuthenticationTicket Unprotect(string protectedText)
        {
            throw new NotImplementedException();
        }
    }
}