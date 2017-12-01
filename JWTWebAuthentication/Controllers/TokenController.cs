using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace JWTWebAuthentication.Controllers
{
    [Authorize]
    [RoutePrefix("api/token")]
    public class TokenController : ApiController
    {
        [Authorize]
        [Route("")]
        public IHttpActionResult Get()
        {
            return Ok("Hello world");
        }
    }
}
