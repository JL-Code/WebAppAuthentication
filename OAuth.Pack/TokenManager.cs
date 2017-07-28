using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace OAuth.Pack
{
    public class TokenManager
    {

        public static string CreateJwtToken(DateTime expires, IEnumerable<Claim> claims)
        {
            //从配置文件中读取 jwt的issuer 发行者 audience 受众  expires 过期时间  key 加密证书
            var issuer = "mecode";
            var audience = "mywebapp";
            var jti = audience + expires.Millisecond + "postman_code";
            jti = MD5Util.GetMD5(jti);
            RSAUtil.TryGetKeyParameters(AppDomain.CurrentDomain.BaseDirectory, true, out RSAParameters rsaPrivatekey);
            //获取签名证书
            //包含用于生成数字签名的加密密钥
            var rsakey = new RsaSecurityKey(rsaPrivatekey);
            var signingCredentials = new SigningCredentials(rsakey, SecurityAlgorithms.RsaSha256Signature);
            var handler = new JwtSecurityTokenHandler();
            var claimsIdentity = new ClaimsIdentity(claims, "JWTTest");

            claimsIdentity.AddClaim(new Claim("jti", jti));
            claimsIdentity.AddClaim(new Claim("now", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")));

            var jwt = handler.CreateEncodedJwt(new SecurityTokenDescriptor()
            {
                Subject = claimsIdentity, //声明的身份
                Audience = audience,
                Expires = expires,
                Issuer = issuer,
                SigningCredentials = signingCredentials
            });
            return jwt;
        }
    }
}
