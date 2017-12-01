using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebAppAuthentication
{
    public class UserIdentity
    {
        public string Name { get; set; }
        public string UserId { get; set; }
        public string Company { get; set; }
        public bool IsAdmin { get; set; }
    }
}