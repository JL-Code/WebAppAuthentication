using Microsoft.Owin.Security.Jwt;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;

namespace JWTWebAuthentication
{
    public class MyIIssuerSecurityTokenProvider : IIssuerSecurityTokenProvider
    {
        private string _issuer;
        public string Issuer => _issuer;

        public IEnumerable<SecurityToken> SecurityTokens => throw new NotImplementedException();

        public MyIIssuerSecurityTokenProvider(string issuer)
        {
            _issuer = issuer;
        }
    }
}