using OAuth.Pack;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.Web.Http;

namespace JwtCustomAuth.Controllers
{
    [RoutePrefix("/token")]
    public class TokensController : ApiController
    {
        [Route("")]
        public IHttpActionResult Post()
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, "userid"),
                new Claim("issuer", "issuer")
            };
            var jwt = TokenManager.CreateJwtToken(DateTime.Now.AddMinutes(30), claims);
            return Ok(jwt);
        }
    }
}
