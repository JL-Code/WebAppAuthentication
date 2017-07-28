using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;

namespace WebAppAuthentication.Controllers
{
    [RoutePrefix("api/Clamis")]
    public class ClamisController : ApiController
    {

        [BearerAuthorize]
        [Route("")]
        public IHttpActionResult Get()
        {
            var identity = User.Identity as ClaimsIdentity;
            var claims = identity.Claims.Select(c => new
            {
                Type = c.Type,
                Value = c.Value
            });
            var userIdentity = User.Identity.ToUserIdentity();
            return Ok(userIdentity);
        }
    }
}
